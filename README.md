# MistralXGo-7B: Fine-Tuned Model for Go Code Generation

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Hugging Face](https://img.shields.io/badge/HuggingFace-Model-orange.svg)

This repository contains **MistralXGo-7B**, a fine-tuned version of the [Mistral-7B](https://huggingface.co/mistralai/Mistral-7B-v0.1) language model optimized for generating Go code based on comments. The model was trained using **LoRA (Low-Rank Adaptation)**, making it lightweight and efficient for deployment.

---

## Table of Contents
1. [Overview](#overview)
2. [Model Details](#model-details)
3. [Usage](#usage)
4. [Training Details](#training-details)
5. [Dataset](#dataset)
6. [Evaluation](#evaluation)
7. [Limitations](#limitations)
8. [Contributing](#contributing)
9. [Citation](#citation)
10. [License](#license)

---

## Overview

The goal of this project is to create a specialized language model that generates Go code from natural language comments. For example, given a comment like:

```go
// Basic routing with Chi.
```

The model generates corresponding Go code:

```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    })
    http.ListenAndServe(":3000", r)
}
```

This model is particularly useful for developers who want to quickly prototype Go applications or explore code generation capabilities.

---

## Model Details

- **Base Model:** [Mistral-7B](https://huggingface.co/mistralai/Mistral-7B-v0.1)
- **Fine-Tuning Method:** LoRA (Low-Rank Adaptation)
- **Quantization:** 4-bit quantization for memory efficiency
- **Max Sequence Length:** 2048 tokens
- **Precision:** Mixed precision (`bf16` or `fp16` depending on hardware)

The model is hosted on Hugging Face Hub at:  
[MistralXGo-7B](https://huggingface.co/devadigaprathamesh/MistralXGo-7B)

---

## Usage

### Installation

Install the required libraries:

```bash
pip install transformers torch
```

### Inference

Load the model and tokenizer from Hugging Face Hub and generate Go code:

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

# Load the model and tokenizer
model_name = "your-username/MistralXGo-7B"
model = AutoModelForCausalLM.from_pretrained(model_name, device_map="auto")
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Generate Go code
prompt = "// Basic routing with Chi."
inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
outputs = model.generate(**inputs, max_new_tokens=256)

# Decode and print the output
print(tokenizer.decode(outputs[0], skip_special_tokens=True))
```

### Example Output

Input:
```go
// Basic routing with Chi.
```

Output:
```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    })
    http.ListenAndServe(":3000", r)
}
```

---

## Training Details

### Dataset
- **Source:** A custom dataset of Go code snippets paired with descriptive comments.
- **Size:** ~1,620 examples (90% training, 10% testing).
- **Preprocessing:** Comments and code were formatted into instruction-output pairs.

### Training Configuration
- **Epochs:** 10
- **Batch Size:** Effective batch size of 8 (per_device_train_batch_size=2, gradient_accumulation_steps=4).
- **Learning Rate:** 2e-4
- **Optimizer:** AdamW 8-bit
- **Mixed Precision:** `bf16` (for Ampere+ GPUs) or `fp16` (for older GPUs).

---

## Dataset

The dataset used for training consists of Go code snippets paired with descriptive comments. Each example follows the format in json:


**Instruction:**  
Basic routing with Chi.

**Code Example**

```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    })
    http.ListenAndServe(":3000", r)
}

```

If you’d like to access the dataset, it can be found here: [Gofiles](data/combined.go)
.

---

## Evaluation

The model was evaluated qualitatively by generating code for various comments and verifying correctness. While no formal quantitative metrics were used, the model demonstrates strong performance in generating syntactically correct and semantically relevant Go code.

---

## Limitations

- **Edge Cases:** The model may struggle with highly complex or domain-specific comments.
- **Ambiguity:** Ambiguous or vague comments may lead to incorrect or incomplete code.
- **Bias:** The model reflects biases present in the training data.

---

## Contributing

Contributions are welcome! If you’d like to improve this project, consider:
- Adding more examples to the dataset.
- Experimenting with different fine-tuning techniques.
- Reporting bugs or suggesting improvements via GitHub Issues.

---

## Citation

If you use this model or dataset in your research, please cite it as follows:

```bibtex
@misc{mistralxgo-7b,
  author = {Prathamesh Devadiga},
  title = {MistralXGo-7B: Fine-Tuned Model for Go Code Generation},
  year = {2023},
  publisher = {GitHub},
  journal = {GitHub Repository},
  howpublished = {\url{https://github.com/devadigapratham/MistralXGo-7B}},
}
```

---

## License

This project is released under the [Apache 2.0 License](LICENSE). You are free to use, modify, and distribute the model and code, provided you include appropriate attribution.

