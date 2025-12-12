#!/usr/bin/env python3
import pathlib
import sys
import nmap_scan
import ai

def main():
    print("=== 🔍 Автоматизированный аудит уязвимостей ===\n")
    try:
        target = input("Введите IP или домен (по умолчанию: scanme.nmap.org): ").strip() or "scanme.nmap.org"
    except (KeyboardInterrupt, EOFError):
        print("\nОперация прервана.")
        sys.exit(1)
    pathlib.Path("scans").mkdir(exist_ok=True)
    safe_name = target.replace(":", "_").replace("/", "_")
    prefix = f"scans/{safe_name}-vuln"
    json_file = f"scans/{safe_name}-clean.json"
    print(f"\n🚀 Сканирование цели: {target}")
    try:
        nmap_scan.run_nmap(target, prefix)
    except FileNotFoundError:
        print("❌ Nmap не найден. Установите nmap и повторите.")
        sys.exit(2)
    except Exception as e:
        print(f"⚠️ Ошибка при запуске Nmap: {e}")
    xml_path = prefix + ".xml"
    if not pathlib.Path(xml_path).exists():
        print(f"❌ Не найден XML отчёт: {xml_path}")
        sys.exit(3)
    data = nmap_scan.parse_xml(xml_path)
    with open(json_file, "w", encoding="utf-8") as f:
        import json
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n✅ Сканирование завершено. Отчёт сохранён: {json_file}")
    print("\n🤖 Запуск анализа с помощью Gemini...\n")
    result, raw_text = ai.analyze_vulns(json_file)
    if raw_text:
        print("\n=== 📋 Полный отчёт Gemini ===\n")
        print(raw_text)
    else:
        print("\n⚠️ Модель не вернула текстовый ответ.")
    if result:
        print("\n=== 💡 Краткое резюме ===\n")
        for rec in result.get("recommendations", []):
            print(f"🧩 {rec['id']} — {rec['priority']}")
            print(f"📄 {rec['title']}")
            print(f"⚠️  {rec['risk'][:160]}...")
            print("—" * 60)
    print("\n🏁 Завершено.\n")

if __name__ == "__main__":
    main()
