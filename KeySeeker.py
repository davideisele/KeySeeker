#!/usr/bin/env python3
# Import
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import multiprocessing as mp
from collections import Counter
import pandas as pd
import math
from tqdm import tqdm
import os
import PySimpleGUI as sg
import argparse


# Dataframe zum speichern der Werte bereitstellen
table = {"Sector Nr:": [], "Possible Keys (HEX)": [], "Entropie": []}
table_df = pd.DataFrame(table)
file_path = os.path.join('.', "possible_keys.csv")

# Commandozeilen Parameter definieren
def parse_arguments():
    parser = argparse.ArgumentParser(description='Program description')

    parser.add_argument('-ui', action='store_true', help='Open user interface')
    parser.add_argument('-ii', '--internal_image', type=str, help='Path to the internal image')
    parser.add_argument('-as', '--adoptable_storage', type=str, help='Path to the adoptable storage image')
    parser.add_argument('-ps', '--partition_start', type=int, help='Partition start (leave empty if unknown)')
    parser.add_argument('-np', '--num_processes', type=int, default=1, help='Number of processes')
    parser.add_argument('-es', '--execution_speed', action='store_true', help='Thorough Search_Funktion')

    args = parser.parse_args()
    return args

# Image Werte erheben
def file_preparation(Internal_Image_path):
    file_size = os.path.getsize(Internal_Image_path)
    process_count = (-(-file_size // 1000000000))
    prozess_size = file_size / process_count
    offset_liste = []

    for i in range(process_count):
        offset_liste.append(i * int(prozess_size))

    return offset_liste

# Image Werte erheben (verkürzt)
def file_preparation2(Internal_Image_path):
    global prozess_size
    file_size = os.path.getsize(Internal_Image_path)
    process_count = (-(-file_size // 1000000000))
    prozess_size = file_size / process_count

    return prozess_size

# Partition-Start Suche
def find_partition(adoptable_storage):
    with open(adoptable_storage, 'rb') as image:
        bootsector = image.read(2048)

        # Bootsector Signatur suchen
        sign = bootsector[510:512]
        if sign == b'U\xaa':
            pass
        else:
            exit()

        # nach EFI Partition suchen
        partition_start = bootsector[454:458]
        partition_start_offset = (int.from_bytes(partition_start, byteorder='little')) * 512

        a = partition_start_offset
        b = partition_start_offset + 8

        if bootsector[a:b] == b'EFI PART':
            pass
        else:
            print("no EFI Found")
            exit()

        partitions_tabelle_start = partition_start_offset + 72  # 0x48
        partitions_tabelle_ende = partitions_tabelle_start + 8
        partitions_tabelle_offset = (int.from_bytes(bootsector[partitions_tabelle_start:partitions_tabelle_ende],
                                                    byteorder='little')) * 512

        # WAS WENN DIE ZU ENTSCHLÜSSELNDE PARTITION NICHT DIE ZWEITE IST

        zweite_partition_eintrag_start = partitions_tabelle_offset + 128
        zweite_partition_offset_start = zweite_partition_eintrag_start + 32
        zweite_partition_offset_ende = zweite_partition_offset_start + 8
        zweite_partition_offset = (int.from_bytes(
            bootsector[zweite_partition_offset_start:zweite_partition_offset_ende],
            byteorder='little')) * 512
        print("zweite Partition Offset (dec): ", zweite_partition_offset)

        return zweite_partition_offset

# Layout für Benutzerschnittstelle erstellen
def create_layout():
    return [[sg.Text("Choose Internal Image")],
            [sg.Input(key='-FILE-'), sg.FileBrowse()],
            [sg.Text("Choose Adoptable Storage Image")],
            [sg.Input(key='-FILE2-'), sg.FileBrowse()],
            [sg.Text('Partition-Start known?')],
            [sg.Radio('Yes', 'RADIO1', key='-YES-'), sg.Radio('No', 'RADIO1', default=True, key='-NO-')],
            [sg.Text('PartitionStart:'), sg.InputText(key='-MSG-', disabled=False)],
            [sg.Text('Parallelprocessing?')],
            [sg.Radio('Yes', 'RADIO2', key='-MULTI-YES-'), sg.Radio('No', 'RADIO2', default=True, key='-MULTI-NO-')],
            [sg.Text('Process Count'), sg.InputText(default_text='1', key='-MULTI-MSG-', disabled=False)],
            [sg.Text('Execution Speed:')],
            [sg.Radio('Fast', 'SPEED', default=True, key='-FAST-'), sg.Radio('Thorough', 'SPEED', key='-THOROUGH-')],
            [sg.Button('OK'), sg.Button('Cancel')]]

# Benutzerschnittstelle erstellen
def user_interface():
    Internal_Image_path = None
    Adoptable_Storage_path = None
    partition_start = None
    num_processes = None
    execution_speed = None

    sg.theme('SystemDefault')
    while True:
        layout = create_layout()
        window = sg.Window('File Browser', layout)

        event, values = window.read()

        if event == sg.WINDOW_CLOSED or event == 'Cancel':
            break

        if event == 'OK':
            Internal_Image_path = values['-FILE-']
            Adoptable_Storage_path = values['-FILE2-']
            partition_start = values['-MSG-']
            num_processes = values['-MULTI-MSG-']
            if values['-FAST-']:
                execution_speed = find_keys
            elif values['-THOROUGH-']:
                execution_speed = find_keys2
            # Fehler in der Eingabe abfangen
            if Internal_Image_path == "":
                sg.popup("No Internal Image Selected")
                continue

            if Adoptable_Storage_path == "":
                sg.popup("No Adoptable Storage Image Selected")
                continue

            if partition_start != "" and not partition_start.isdigit():
                sg.popup("Only Integer Values for Partition Start")
                continue

            # Wenn der Benutzer den Partitionsstart kennt, wird sein Wert übergeben
            if values['-YES-']:
                partition_start = int(values['-MSG-'])

            # Wenn der Benutzer "Nein" auswählt, wird das Textfeld deaktiviert
            if values['-NO-']:
                if Adoptable_Storage_path is not None:
                    partition_start = find_partition(Adoptable_Storage_path)

            # Fehlereldung bei der Eingabe für Multiprozessing abfangen
            if not num_processes.isdigit():
                sg.popup("Only Integer Value for Multiprocessing")
                continue

            # Wenn der Wert über der Anzahl der verfügbaren Kerne ist, wird die maximale Anzahl an Prozessen verwendet
            if values['-MULTI-YES-']:
                if int(values['-MULTI-MSG-']) > os.cpu_count():
                    num_processes = os.cpu_count()
                else:
                    num_processes = int(values['-MULTI-MSG-'])

            # Wenn Multiprocessing abgelehnt wird, wird nur ein Prozess verwendet
            if values['-MULTI-NO-']:
                num_processes = 1
                break
            break
    window.close()
    return Internal_Image_path, Adoptable_Storage_path, partition_start, num_processes, execution_speed

# Entropie-Berechnung definieren
def calc_entropy(key):
    list1 = []
    prob = []

    for b in key:
        int(b)
        list1.append(hex(b))

    length = len(list1)

    Counter(list1).keys()  # zählt wieviele unterschiedliche Bytes auftreten
    Counter(list1).values()  # zählt die Anzahl an gleichen Bytes

    for i in Counter(list1).values():
        cv = i / length
        prob.append(cv)

    # Entropiefunktion
    e = 0
    for p in prob:
        e += (-(p * math.log2(p)))
    e = e / math.log2(length)

    return e

# Schlüsselsuche definieren
def find_keys(args):
    offset, prozessSize, Internal_Image_path = args
    table = {"Sector Nr:": [], "Possible Keys (HEX)": [], "Entropie": []}
    table_df1 = pd.DataFrame(table)
    table_df1 = table_df1[0:0]
    start = 0
    end = 512
    sector_nr = int(offset / 512)
    var = int(prozessSize / 512)
    with open(Internal_Image_path, 'rb') as drive:
        drive.seek(offset)
        one_GiB = drive.read(int(prozessSize))
        for i in range(var):
            try:
                one_sector = one_GiB[start:end]
                first_bytes = one_sector[0:16]
                e1 = calc_entropy(first_bytes)
                if e1 > 0.9:
                    rest_bytes = one_sector[16:]
                    e2 = calc_entropy(rest_bytes)
                    if e2 < 0.4375:
                        table_df1.loc[len(table_df1)] = sector_nr, first_bytes.hex(), e1
            except Exception as e:
                print("Puffer cant be filled", e)
            start = start + 512
            end = end + 512
            sector_nr = sector_nr + 1

    return table_df1


def find_keys2(args):
    offset, prozessSize, Internal_Image_path = args
    table = {"Sector Nr:": [], "Possible Keys (HEX)": []}
    table_df1 = pd.DataFrame(table)
    table_df1 = table_df1[0:0]
    start = 0
    end = 512
    sector_nr = int(offset / 512)
    var = int(prozessSize / 512)
    with open(Internal_Image_path, 'rb') as drive:
        drive.seek(offset)
        one_GiB = drive.read(int(prozessSize))
        for i in range(var):
            try:
                one_sector = one_GiB[start:end]
                first_bytes = one_sector[0:16]
                if first_bytes != 16 * b'\x00':
                    rest_bytes = one_sector[16:]
                    if rest_bytes == 496 * b'\x00':
                        table_df1.loc[len(table_df1)] = sector_nr, first_bytes.hex()
            except Exception as e:
                print("Puffer cant be filled", e)
            start = start + 512
            end = end + 512
            sector_nr = sector_nr + 1

    return table_df1


# Ableitung des Initialisierungsvektor definieren
def derive_IV(key, block_number):
    derived_key = SHA256.new(key).digest()
    derived_IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    derived_data = block_number.to_bytes(16, byteorder='little', signed=False)

    return AES.new(derived_key, AES.MODE_CBC, derived_IV).encrypt(derived_data)

# Entschlüsselung definieren
def decrypt(cipher_text, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text)

# Test-Funktion für gefundene potenielle Schlüssel
def test_key():
    keys_df = table_df.drop(table_df.columns[[0, 2]], axis=1)
    final_key = None
    for x in range(len(keys_df)):
        key_str = keys_df.iloc[x, 0]
        key = bytes.fromhex(key_str)
        iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        block_size = 512
        block_number = -1

        with open(Adoptable_Storage_path, 'rb') as f:
            f.seek(partition_start)
            while True:
                block = f.read(block_size)
                block_number = block_number + 1

                if not block:
                    break

                iv = derive_IV(key, block_number)
                plaintext = decrypt(block, key, iv)

                if block_number == 10:
                    check_encryption = plaintext[:4]

                    if check_encryption == b'\x10\x20\xf5\xf2':
                        final_key = key
                        break

                if block_number == 2:
                    check_encryption = plaintext[56:58]

                    if check_encryption == b'\x53\xEF':
                        final_key = key
                        break

                if block_number >= 10:
                    break

    # if final_key is not None:
    #     break

    if final_key is None:
        print("No key found")
    else:
        print("Key found: " + final_key.hex())

    return final_key

# Main-Methode
if __name__ == '__main__':
    args = parse_arguments()
    if args.ui:
        Internal_Image_path, Adoptable_Storage_path, partition_start, num_processes, execution_speed = user_interface()
    else:
        Internal_Image_path = args.internal_image
        Adoptable_Storage_path = args.adoptable_storage
        partition_start = args.partition_start
        num_processes = args.num_processes

    if args.partition_start is None:
        partition_start = find_partition(Adoptable_Storage_path)

    if args.execution_speed:
        run_function = find_keys
    else:
        run_function = find_keys2

    if Internal_Image_path == "":
        print("No Internal Image Selected")
    elif Adoptable_Storage_path == "":
        print("No Adoptable Storage Image Selected")
    else:
        prozess_size = file_preparation2(Internal_Image_path)
        print("cpu:", num_processes)
        print("prozessSize:", prozess_size)
        offset_liste = file_preparation(Internal_Image_path)
        offset = offset_liste

        task_params = [(o, prozess_size, Internal_Image_path) for o in offset]

        pool = mp.Pool(processes=num_processes)

        with tqdm(total=len(offset)) as progress_bar:
            for result in pool.imap_unordered(run_function, task_params):
                table_df = table_df._append(result)
                progress_bar.update()

        pool.close()
        pool.join()
        table_df = table_df.sort_values(by=['Entropie'], ascending=False)
        table_df.to_csv(file_path, mode='a', index=False,
                        sep='\t',
                        header=False)

        test_key()
