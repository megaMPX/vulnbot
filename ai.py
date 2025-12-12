#!/usr/bin/env python3
import os
import sys
import json
import re
from groq import Groq
import config

API_KEY = config.GROQ_API_KEY

if not API_KEY:
    print("ERROR: set GROQ_API_KEY in config.py", file=sys.stderr)
    sys.exit(1)

MODEL_NAME = getattr(config, "GROQ_MODEL")

client = Groq(api_key=API_KEY)


def load_json(path):
    if not os.path.exists(path):
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_prompt(vuln_json):
    prompt = (
        "Ты системный аналитик по кибербезопасности.\n"
        "Проанализируй JSON отчёт об уязвимостях.\n\n"
        "‼️ ВАЖНО:\n"
        "- Каждая уязвимость уникальна.\n"
        "- Используй суть конкретного CVE (RCE, DoS, overflow, bypass и т.д.).\n"
        "- В 'steps' указывай конкретные действия: версии, директивы, команды.\n"
        "- В 'verify' указывай конкретные команды и методы тестирования.\n"
        "- **Запрещено** использовать теги <think> или любые пояснительные комментарии.\n"
        "- Верни строго JSON, только в формате:\n"
        "{\n"
        "  \"recommendations\": [\n"
        "    {\n"
        "      \"id\": \"CVE-XXXX-XXXXX\",\n"
        "      \"title\": \"Краткий заголовок (тип уязвимости)\",\n"
        "      \"risk\": \"Подробное описание угрозы\",\n"
        "      \"priority\": \"High | Medium | Low\",\n"
        "      \"steps\": [\"конкретные шаги устранения\"],\n"
        "      \"verify\": [\"конкретные действия для проверки\"],\n"
        "      \"references\": [\"URL источников\"]\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        f"JSON отчёт:\n{json.dumps(vuln_json, ensure_ascii=False, indent=2)}"
    )
    return prompt


def repair_ai_json(text):
    text = re.sub(r'(["\'])\s*\*\s*\d+', r'\1', text)

    text = re.sub(r'(["\'])\s*\+\s*(["\'])', '', text)


    text = re.sub(r',\s*([\]}])', r'\1', text)
    
    return text


def analyze_vulns(input_path, output_path="recommendations.json"):
    vuln_data = load_json(input_path)
    prompt = build_prompt(vuln_data)

    print(f"[+] Sending request to Groq model {MODEL_NAME}...")

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "Ты эксперт по анализу уязвимостей."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_completion_tokens=8000,
            top_p=1,
            stream=False
        )

        text = response.choices[0].message.content


        text = re.sub(r"<think.*?</think>", "", text, flags=re.IGNORECASE | re.DOTALL)

    except Exception as e:
        print("API error:", e, file=sys.stderr)
        return None, None


    with open("recommendations_raw.txt", "w", encoding="utf-8") as f:
        f.write(text)

    try:

        clean_text = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE)
        clean_text = clean_text.replace("```", "").strip()


        start = clean_text.find("{")
        end = clean_text.rfind("}")

        if start == -1 or end == -1:
            raise json.JSONDecodeError("No JSON brackets found", clean_text, 0)

        json_content = clean_text[start : end + 1]


        repaired_json = repair_ai_json(json_content)


        result = json.loads(repaired_json)

  
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print(f"[+] Saved: {output_path}")
        return result, text

    except json.JSONDecodeError as e:
        print("\nJSON error:", e)
        # print("Repaired text snippet:", repaired_json[:500]) # раскомментировать для дебага
        return None, text


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ai.py vuln_report.json", file=sys.stderr)
        sys.exit(3)

    input_path = sys.argv[1]
    analyze_vulns(input_path)


if __name__ == "__main__":
    main()