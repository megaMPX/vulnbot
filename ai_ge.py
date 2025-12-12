#!/usr/bin/env python3
import os
import sys
import json
import google.generativeai as genai
import config

API_KEY = os.environ.get("GOOGLE_API_KEY")
API_KEY = config.GOOGLE_API_KEY
if not API_KEY:
    print("ERROR: set GOOGLE_API_KEY environment variable", file=sys.stderr)
    sys.exit(1)

genai.configure(api_key=API_KEY)
MODEL_NAME = "gemini-2.5-flash-lite"

def load_json(path):
    if not os.path.exists(path):
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def build_prompt(vuln_json):
    prompt = (
        "Ты опытный инженер по кибербезопасности. "
        "Проанализируй следующий JSON отчёт об уязвимостях и для каждой уязвимости "
        "составь рекомендации(ничего не пиши кроме отчета):\n"
        "1. Краткое описание риска (на русском);\n"
        "2. Приоритет (High, Medium или Low);\n"
        "3. Конкретные шаги устранения (patch, настройка, команды);\n"
        "4. Проверку после исправления;\n"
        "5. Ссылки на источники (если есть CVE или официальные советы).\n\n"
        "Выведи ответ в формате JSON с ключом 'recommendations', где каждый элемент — это объект "
        "с полями id, title, risk, steps, verify, references.(НЕ ПОВТОРЯЙ ОДИН И ТОТ ЖЕ steps во всех пунктах)\n\n"
        "JSON отчёт ниже:\n"
        f"{json.dumps(vuln_json, ensure_ascii=False, indent=2)}"
    )
    return prompt

def analyze_vulns(input_path, output_path="recommendations.json"):
    vuln_data = load_json(input_path)
    model = genai.GenerativeModel(MODEL_NAME)
    prompt = build_prompt(vuln_data)
    print(f"[+] Send {MODEL_NAME}...")

    try:
        response = model.generate_content(prompt)
        text = response.text
    except Exception as e:
        print("API error:", e, file=sys.stderr)
        return None, None

    import re, json
    try:
        clean_text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE)
        json_match = re.search(r"\{[\s\S]*\}", clean_text)
        if json_match:
            clean_text = json_match.group(0)

        result = json.loads(clean_text)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print(f"[+] Save {output_path}")
        return result, text

    except json.JSONDecodeError:
        raw_path = "recommendations_raw.txt"
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"⚠️ Ответ модели не в JSON. Сохранён как текст в {raw_path}")
        return None, text

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ai.py vuln_report.json", file=sys.stderr)
        sys.exit(3)

    input_path = sys.argv[1]
    analyze_vulns(input_path)

if __name__ == "__main__":
    main()
