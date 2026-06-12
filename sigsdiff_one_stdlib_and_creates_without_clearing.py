# -*- coding: utf-8 -*-
import os
import ida_funcs
import ida_name
import ida_auto
from ida_idaapi import BADADDR
from collections import defaultdict

STDLIB_SIG = r"C:\Users\hecker\Desktop\newsigs\1.86.0-x86_64-unknown-linux-gnu-release-default.sig"
CRATES_DIR = r"C:\Users\hecker\Desktop\sigs_for_crates"
OUTPUT_FILE = r"C:\Users\hecker\Desktop\sig_name_history.txt"

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
        # Принудительно переименовываем в sub_XXXX
        ida_name.set_name(ea, f"sub_{ea:X}", ida_name.SN_FORCE)
        func = ida_funcs.get_next_func(ea)

def apply_signature(sig_path):
    print(f"Applying {sig_path} ...")
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
    """Собирает сигнатуры с читаемыми метками (путь относительно CRATES_DIR для крейтов)."""
    sigs = []
    # Stdlib-сигнатура первой
    if os.path.exists(STDLIB_SIG):
        sigs.append((STDLIB_SIG, os.path.basename(STDLIB_SIG)))
    # Сигнатуры крейтов
    for root, dirs, files in os.walk(CRATES_DIR):
        for f in files:
            if f == "signature_output.sig":
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, CRATES_DIR)  # например "aes-0.8.4/signature_output.sig"
                sigs.append((full_path, rel_path))
    return sigs

sig_files = collect_sig_files()
print(f"Total signatures to apply: {len(sig_files)}")
for path, label in sig_files:
    print(f"  {label}")

# Запоминаем исходные имена
print("Saving original names...")
original_names = get_function_names()

# История: ea -> список (step_index, сигнатура, имя)
history = defaultdict(list)
for ea, name in original_names.items():
    history[ea].append((-1, "original", name))

# Для каждой сигнатуры: сброс имён, применение, запись результата
for idx, (sig_path, sig_label) in enumerate(sig_files):
    print(f"Resetting names for {sig_label}...")
    reset_all_names()
    if not apply_signature(sig_path):
        continue
    new_snapshot = get_function_names()
    for ea, new_name in new_snapshot.items():
        history[ea].append((idx, sig_label, new_name))

# Сохраняем историю
print(f"Writing history to {OUTPUT_FILE} ...")
with open(OUTPUT_FILE, "w") as f:
    for ea in sorted(history.keys()):
        entries = history[ea]
        initial_name = entries[0][2] if entries[0][1] == "original" else "??"
        line = f"{ea:08X}: {initial_name}"
        for step_idx, sig_name, name in entries[1:]:
            line += f"  ->  [{sig_name}: {name}]"
        f.write(line + "\n")

print("Done.")