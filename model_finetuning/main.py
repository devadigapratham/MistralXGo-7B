import re
from datasets import Dataset
from unsloth import FastLanguageModel
from transformers import TrainingArguments
from trl import SFTTrainer
import torch

def parse_go_file(file_path):
    """Parse a Go file with // comments and code into a dataset."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Regex to extract comment-code pairs
    pattern = r'// (.*?)\n(.*?)(?=\n// |\Z)'
    matches = re.findall(pattern, content, re.DOTALL)
    
    # Create dataset
    return [{"instruction": c.strip(), "input": "", "output": code.strip()} 
            for c, code in matches]

# Load my dataset (update the path to my Go file)
dataset = parse_go_file("combined.go")
dataset = Dataset.from_list(dataset).train_test_split(test_size=0.1)

max_seq_length = 2048  # Choose any! We auto-support RoPE Scaling internally!
dtype = None  # Let Unsloth auto-detect the best dtype (bfloat16 or float16)
load_in_4bit = True  # Use 4-bit quantization to reduce memory usage.

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/mistral-7b-bnb-4bit",
    max_seq_length=max_seq_length,
    dtype=dtype,  # Auto-detect dtype
    load_in_4bit=load_in_4bit,
    attn_implementation="xformers",  # Use xformers for faster attention
)

model = FastLanguageModel.get_peft_model(
    model,
    r=16,  # Choose any number > 0! Suggested: 8, 16, 32, 64, 128
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,  # Supports any, but = 0 is optimized
    bias="none",     # Supports any, but = "none" is optimized
    use_gradient_checkpointing="unsloth",  # True or "unsloth" for very long context
    random_state=3407,
    use_rslora=False,  # We support rank stabilized LoRA
    loftq_config=None,  # And LoftQ
)

# %% [Formatting Prompts]
EOS_TOKEN = tokenizer.eos_token  # Must add EOS_TOKEN
def formatting_prompts_func(examples):
    instructions = examples["instruction"]
    inputs = examples["input"]
    outputs = examples["output"]
    texts = []
    for instruction, input, output in zip(instructions, inputs, outputs):
        # Must add EOS_TOKEN, otherwise the generation will go on forever!
        text = f"// {instruction}\n\n{output}{EOS_TOKEN}"
        texts.append(text)
    return {"text": texts}

# Apply formatting to the dataset
dataset = dataset.map(formatting_prompts_func, batched=True)

# %% [Training Arguments]
training_args = TrainingArguments(
    per_device_train_batch_size=2,
    gradient_accumulation_steps=4,
    warmup_steps=5,
    num_train_epochs=10,  # Run for 10 epochs
    learning_rate=2e-4,
    fp16=torch.cuda.is_available() and torch.cuda.get_device_capability()[0] < 8,  # Enable FP16 for older GPUs
    bf16=torch.cuda.is_available() and torch.cuda.get_device_capability()[0] >= 8,  # Enable BF16 for Ampere+ GPUs
    tf32=False, 
    logging_steps=1,
    optim="adamw_8bit",
    weight_decay=0.01,
    lr_scheduler_type="linear",
    seed=3407,
    output_dir="outputs",
    report_to="none",  # Disable WandB and other loggers
)

# %% [Trainer Setup]
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset["train"],
    eval_dataset=dataset["test"],
    dataset_text_field="text",
    max_seq_length=max_seq_length,
    dataset_num_proc=2,
    packing=False,  # Can make training 5x faster for short sequences.
    args=training_args,
)

# Align model dtype with training arguments
if training_args.bf16:
    model.config.torch_dtype = torch.bfloat16
else:
    model.config.torch_dtype = torch.float16

# %% [Start Training]
print("Starting training...")
trainer_stats = trainer.train()
print("Training completed!")

# %% [Inference]
FastLanguageModel.for_inference(model)  # Enable native 2x faster inference
prompt = "// Basic routing with Chi."
inputs = tokenizer([prompt], return_tensors="pt").to("cuda")

# Generate response
outputs = model.generate(**inputs, max_new_tokens=256)
print(tokenizer.decode(outputs[0]))

# %% [Save Model]
model.save_pretrained("MistralXGo-7Bpt2")  # Local saving
tokenizer.save_pretrained("MistralXGo-7Bpt2")
