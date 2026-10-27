"""
Train Qwen with Unsloth for Cybersecurity SOC Triage
===================================================
Uses Unsloth (2x faster, 70% less VRAM, native QLoRA 4-bit)
and exports directly to GGUF format for Ollama!

Requirements:
  pip install unsloth "torch" "transformers" "trl" "peft" "bitsandbytes"

Run:
  python scripts/train_unsloth_qwen.py
"""

import os
import sys
from pathlib import Path

DATASET_PATH = Path(__file__).resolve().parent.parent / "exports" / "unsloth_training_dataset.jsonl"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "exports" / "qwen_soc_finetuned"

def train_with_unsloth(
    base_model: str = "unsloth/Qwen2.5-14B-Instruct-bnb-4bit",
    max_seq_length: int = 2048,
    epochs: int = 1,
    learning_rate: float = 2e-4,
):
    print("=" * 70)
    print("UNSLOTH FINE-TUNING PIPELINE FOR SOC AI TRIAGE")
    print("=" * 70)
    print(f"[*] Base Model   : {base_model}")
    print(f"[*] Dataset      : {DATASET_PATH}")
    print(f"[*] Max Seq Len  : {max_seq_length}")
    print(f"[*] Output Dir   : {OUTPUT_DIR}")
    print("=" * 70)

    try:
        import torch
        from unsloth import FastLanguageModel
        from unsloth.chat_templates import get_chat_template
        from datasets import load_dataset
        from trl import SFTTrainer
        from transformers import TrainingArguments
    except ImportError:
        print("[!] Unsloth or PyTorch dependencies not detected in current environment.")
        print("[!] To run fine-tuning on a GPU machine (PC Kantor / Google Colab):")
        print("    pip install --upgrade pip")
        print("    pip install unsloth 'xformers' 'trl' 'peft' 'bitsandbytes'")
        return

    # 1. Load Pre-quantized 4-bit Model
    print("[1/5] Loading 4-bit Base Model with Unsloth...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=base_model,
        max_seq_length=max_seq_length,
        load_in_4bit=True,
    )

    # 2. Add LoRA Adapters (PEFT)
    print("[2/5] Initializing LoRA Adapters (r=16, alpha=16)...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_alpha=16,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    # 3. Format Dataset with Qwen Chat Template
    print("[3/5] Formatting dataset with Qwen Chat Template...")
    tokenizer = get_chat_template(tokenizer, chat_template="qwen-2.5")

    def formatting_prompts_func(examples):
        convos = examples["conversations"]
        texts = [tokenizer.apply_chat_template(convo, tokenize=False, add_generation_prompt=False) for convo in convos]
        return {"text": texts}

    raw_dataset = load_dataset("json", data_files=str(DATASET_PATH), split="train")
    dataset = raw_dataset.map(formatting_prompts_func, batched=True)

    # 4. Train Model with SFTTrainer
    print(f"[4/5] Training model on {len(dataset)} samples...")
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=max_seq_length,
        dataset_num_proc=2,
        packing=False,
        args=TrainingArguments(
            per_device_train_batch_size=2,
            gradient_accumulation_steps=4,
            warmup_steps=10,
            num_train_epochs=epochs,
            learning_rate=learning_rate,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=5,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="linear",
            seed=42,
            output_dir="exports/unsloth_checkpoints",
        ),
    )
    trainer.train()

    # 5. Export to GGUF Format for Ollama
    print("[5/5] Exporting fine-tuned model to 4-bit GGUF for Ollama...")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    model.save_pretrained_gguf(
        str(OUTPUT_DIR),
        tokenizer,
        quantization_method="q4_k_m"
    )

    print("\n" + "=" * 70)
    print("FINE-TUNING COMPLETED SUCCESSFULLY!")
    print(f"GGUF File ready at: {OUTPUT_DIR}")
    print("To load into Ollama on PC Kantor:")
    print(f"  1. Buat Modelfile: FROM {OUTPUT_DIR}/unsloth.Q4_K_M.gguf")
    print("  2. Jalankan: ollama create qwen-soc-retrained -f Modelfile")
    print("=" * 70)

if __name__ == "__main__":
    train_with_unsloth()
