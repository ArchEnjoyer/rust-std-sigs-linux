# rust-std-sigs-linux

Этот репозиторий содержит FLIRT сигнатуры языка rust (только для linux) для IDA Pro, смотрите https://github.com/N0fix/rust-std-sigs

This repo contains rust FLIRT sigs (only linux) for IDA Pro, check out https://github.com/N0fix/rust-std-sigs 


Файлы  create_sigs_for_crates.sh и create_sigs_for_stdlib.sh нужны для автоматизации создания сигнатур для stdlib и крейтов (их можно указать в скриптах)

The files create_sigs_for_crates.sh and create_sigs_for_stdlib.sh are designed to automate the creation of signatures for stdlib and crates (you can write them in scripts)


ida_crate_sigs.py может быть использован для простой загрузки всех сигнатур для крейтов

ida_crate_sigs.py can be used to easily download all signatures for crates


sigsdiff_many_stdlibs_with_clearing.py и sigsdiff_one_stdlib_and_creates_without_clearing.py используются для создания файла с историей переименований имён функций, что может быть полезно для выявления используемых в программе крейтов

sigsdiff_many_stdlibs_with_clearing.py and sigsdiff_one_stdlib_and_creates_without_clearing.py are used to create a file with a history of function name renamings, which can be useful for identifying crates used in a program


*00019301: sub_19301  ->  [1.86.0-x86_64-unknown-linux-gnu-release-default.sig: sub_19301]  ->  [aes-0.8.4\signature_output.sig: ZN3aes10autodetect14aes_intrinsics8init_get10init_inner11cpuid_count17h96b9f6f500e1a576E]  ->  [aes-0.9.0-pre\signature_output.sig: _ZN3aes10autodetect14aes_intrinsics8init_get10init_inner11cpuid_count17h3823ac0709bc241bE]  ->  [chrono-0.4.40\signature_output.sig: sub_19301]  -> ...*
