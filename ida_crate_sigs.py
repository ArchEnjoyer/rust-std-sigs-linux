import os
import ida_funcs
import ida_auto

# Укажите путь к папке sigs_for_crates (можно заменить на свой)
SIG_DIR = r"C:\Users\hecker\Desktop\sigs_for_crates"

def apply_all_signatures(sig_root):
    applied = 0
    failed = 0
    skipped = 0

    # Обходим все подпапки
    for crate_dir in os.listdir(sig_root):
        crate_path = os.path.join(sig_root, crate_dir)
        if not os.path.isdir(crate_path):
            continue

        sig_file = os.path.join(crate_path, "signature_output.sig")
        if not os.path.isfile(sig_file):
            print(f"[SKIP] {crate_dir}: файл signature_output.sig не найден")
            skipped += 1
            continue

        print(f"[LOAD] {crate_dir} ...")
        # Загружаем сигнатурный файл
        if ida_funcs.plan_to_apply_idasgn(sig_file):
            # Даём автоанализу время применить сигнатуру
            ida_auto.auto_wait()
            print(f"[OK]   {crate_dir} успешно применён")
            applied += 1
        else:
            print(f"[FAIL] {crate_dir}: ошибка загрузки сигнатуры")
            failed += 1

    print("\n=== Итого ===")
    print(f"Успешно применено: {applied}")
    print(f"Ошибок загрузки:   {failed}")
    print(f"Пропущено:          {skipped}")

if __name__ == "__main__":
    if not os.path.isdir(SIG_DIR):
        print(f"Ошибка: папка {SIG_DIR} не существует.")
    else:
        apply_all_signatures(SIG_DIR)