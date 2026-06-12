# -*- coding: utf-8 -*-
import os
import ida_funcs
import ida_name
import ida_auto
from collections import defaultdict

SIG_DIR = r"C:\Users\hecker\Desktop\newsigs"
OUTPUT_FILE = r"C:\Users\hecker\Desktop\sig_name_history_filtered.txt"

# Новый список сигнатур (все версии из вашего сообщения)
TARGET_VERSIONS = [
    "1.80.0", "1.80.1", "1.81.0", "1.82.0",
    "1.83.0", "1.84.0", "1.84.1", "1.85.0",
    "1.85.1", "1.86.0", "1.94.0"
]

def get_function_names():
    """Возвращает словарь {ea: name} для всех функций в базе."""
    result = {}
    func = ida_funcs.get_next_func(0)
    while func:
        ea = func.start_ea
        name = ida_name.get_ea_name(ea)
        result[ea] = name if name else ""
        func = ida_funcs.get_next_func(ea)
    return result

def reset_all_names():
    """Сбрасывает имена всех функций на sub_XXXX (чтобы FLIRT мог перезаписать)."""
    func = ida_funcs.get_next_func(0)
    while func:
        ea = func.start_ea
        ida_name.set_name(ea, f"sub_{ea:X}", ida_name.SN_FORCE)
        func = ida_funcs.get_next_func(ea)

def apply_signature(sig_path):
    """Применяет сигнатуру FLIRT."""
    print(f"Applying {os.path.basename(sig_path)} ...")
    if not os.path.exists(sig_path):
        print(f"  [ERROR] File not found: {sig_path}")
        return False
    if not ida_funcs.plan_to_apply_idasgn(sig_path):
        print(f"  [ERROR] plan_to_apply_idasgn failed")
        return False
    ida_auto.auto_wait()
    print("  OK")
    return True

def collect_sig_files():
    """Собирает только те .sig файлы из SIG_DIR, чьи имена содержат TARGET_VERSIONS."""
    if not os.path.isdir(SIG_DIR):
        print(f"[ERROR] Directory not found: {SIG_DIR}")
        return []
    sigs = []
    for fname in os.listdir(SIG_DIR):
        if not fname.endswith(".sig"):
            continue
        for ver in TARGET_VERSIONS:
            if ver in fname:
                full_path = os.path.join(SIG_DIR, fname)
                sigs.append((full_path, fname))
                break
    sigs.sort(key=lambda x: x[1])
    return sigs

def is_technical_name(name):
    """Возвращает True, если имя выглядит как техническое (sub_XXXX или nullsub_X)."""
    return name.startswith("sub_") or name.startswith("nullsub_")

def main():
    sig_files = collect_sig_files()
    print(f"Total signatures to apply: {len(sig_files)}")
    for path, label in sig_files:
        print(f"  {label}")

    if not sig_files:
        print("No matching signatures found. Exiting.")
        return

    # 1. Запоминаем исходные имена
    print("Saving original names...")
    original_names = get_function_names()

    # 2. История: ea -> список (step_index, сигнатура, имя)
    history = defaultdict(list)
    for ea, name in original_names.items():
        history[ea].append((-1, "original", name))

    # 3. Для каждой выбранной сигнатуры: сброс, применение, запись результата
    for idx, (sig_path, sig_label) in enumerate(sig_files):
        print(f"\n--- Step {idx+1}: resetting names for {sig_label} ---")
        reset_all_names()
        if not apply_signature(sig_path):
            continue
        new_snapshot = get_function_names()
        for ea, new_name in new_snapshot.items():
            history[ea].append((idx, sig_label, new_name))

    # 4. Сохраняем историю, исключая функции с техническими именами в конце
    print(f"Writing history to {OUTPUT_FILE} ...")
    kept = 0
    skipped = 0
    with open(OUTPUT_FILE, "w") as f:
        for ea in sorted(history.keys()):
            entries = history[ea]
            # Последнее имя (после всех сигнатур)
            final_name = entries[-1][2]
            # Пропускаем, если финальное имя техническое
            if is_technical_name(final_name):
                skipped += 1
                continue
            kept += 1
            initial_name = entries[0][2] if entries[0][1] == "original" else "??"
            line = f"{ea:08X}: {initial_name}"
            for step_idx, sig_name, name in entries[1:]:
                line += f"  ->  [{sig_name}: {name}]"
            f.write(line + "\n")
    print(f"Done. Kept {kept} functions (with non-technical final name), skipped {skipped}.")

if __name__ == "__main__":
    main()