#!/bin/bash

# Se non hai installato python2 e hai python3 cambia python->python3 nelle funtion
# di Encryption e Decryption (nella funcition password è gia python3 richiamato)
# Stessa cosa per lanciare pyLock.py [usa: pyhton3 pyLock.py]

function sleep() {
  echo ""
  read -p "Per contiunare premi [ENTER], altrimenti, [CTRL + C] per uscire"
}

# Directory Attuale
function workDir() {
  echo -e "\n --============[Directory Attuale]============-- \n "
  ls
  echo -e "\n --===========================================-- \n "
  sleep
}

function password() {
  echo -e "\n# Genera la tua password personale \n "
  python3 pyLock.py
  echo -e "\n La password non verrà memorizzata da nessuna parte!
 Salvala e Ricocorda per cosa la usi \n "
  sleep
}

# Key generator
function key32() {
  echo -e "\n~ key32 generator ~"
  read -p "[key32-nome]> " key
  LC_CTYPE=C tr -dc A-Za-z0-9_\- </dev/urandom | head -c 32 | xargs >$key
  #workDir
  showKey=$(cat $key)
  echo -e "key: $showKey"
  echo -e "\n==> La tua key32 '$key' è stata generate con successo!"
  echo "$key" >>.gitignore
  echo -e "==> La tua key32 '$key' è stata aggiunta a .gitignore! (Cartella_Nascosta)"
  chmod 0600 $key
  echo -e "==> Autorizzazione della key32 '$key' !"
  sleep
}

function key64() {
  echo -e "\n~ key64 generator ~"
  read -p "[key64-nome]> " key
  LC_CTYPE=C tr -dc A-Za-z0-9_\- </dev/urandom | head -c 64 | xargs >$key
  #workDir
  showKey=$(cat $key)
  echo -e "key: $showKey"
  echo -e "\n==> La tua key64 '$key' è stata generate con successo!"
  echo "$key" >>.gitignore
  echo -e "==> La tua key64 '$key' è stata aggiunta a .gitignore! (Cartella_Nascosta)"
  chmod 0600 $key
  echo -e "==> Autorizzazione della key64 '$key' !"
  sleep
}

function key128() {
  echo -e "\n~ key128 generator ~"
  read -p "[key32-nome]> " key
  LC_CTYPE=C tr -dc A-Za-z0-9_\- </dev/urandom | head -c 128 | xargs >$key
  #workDir
  showKey=$(cat $key)
  echo -e "key: $showKey"
  echo -e "\n==> La tua key128 '$key' è stata generate con successo!"
  echo "$key" >>.gitignore
  echo -e "==> La tua key128 '$key' è stata aggiunta a .gitignore! (Cartella_Nascosta)"
  chmod 0600 $key
  echo -e "==> Autorizzazione della key128 '$key' !"
  sleep
}

function key256() {
  echo -e "\n~ key256 generator ~"
  read -p "[key32-nome]> " key
  LC_CTYPE=C tr -dc A-Za-z0-9_\- </dev/urandom | head -c 256 | xargs >$key
  #workDir
  showKey=$(cat $key)
  echo -e "key: $showKey"
  echo -e "\n==> La tua key256 '$key' è stata generate con successo!"
  echo "$key" >>.gitignore
  echo -e "==> La tua key256 '$key' è stata aggiunta a .gitignore! (Cartella_Nascosta)"
  chmod 0600 $key
  echo -e "==> Autorizzazione della key256 '$key' !"
  sleep
}

# Senza key
function encryptWithoutKey() {
  echo -e "\n~ Encrypt file senza key ~\n"
  #workDir
  echo "Inserisci il percorso del file/directory"
  echo ""
  read -p "[file\dir]> " file
  echo ""
  start=$(date +%s.%N)
  core=$(python pyLock.py -P secret --lock $file)
  end=$(date +%s.%N)
  runtime=$(python -c "print(${end} - ${start})")
  echo "Tempo impiegato per cifrare = $runtime [secondi]"
  echo ""
  #workDir
  echo -e "==> Il tuo file è stato cifrato con successo! (senza key)"
  sleep
}

function decryptWithoutKey() {
  echo -e "\n~ Decrypt file senza key ~\n"
  #workDir
  echo "Inserisci il percorso del file/directory (.locked)
[SOLO SE E' UN FILE ANCHE ESTENSIONE .locked dopo il 'nome_file.estensione_originale']"
  echo ""
  read -p "[file\dir]> " file
  echo ""
  start=$(date +%s.%N)
  core=$(python pyLock.py -P secret --unlock $file)
  end=$(date +%s.%N)
  runtime=$(python -c "print(${end} - ${start})")
  echo "Tempo impiegato per decifrare = $runtime [secondi]"
  echo ""
  #workDir
  echo -e "==> Il tuo file è stato decodifciato con successo! (senza key)"
  sleep
}

# Con key
function encryptWithKey() {
  echo -e "\n~ Encrypt file con key ~\n"
  read -p "Ottieni key (key32 or key64 or ... ) prima di contiunare, [ENTER] ..." tmp
  #workDir
  echo "Inserisci il percorso del file/directory"
  echo ""
  read -p "[file\dir]> " file
  echo "Inserisci il nome della tua key"
  read -p "[key]> " key
  echo ""
  start=$(date +%s.%N)
  core=$(python pyLock.py -p $key -l $file)
  end=$(date +%s.%N)
  runtime=$(python -c "print(${end} - ${start})")
  echo "Tempo impiegato per cifrare = $runtime [secondi]"
  #workDir
  echo ""
  echo -e "==> Il tuo file è stato cifrato con successo! (con key '$key')"
  sleep
}

function decryptWithKey() {
  echo -e "\n~ Decrypt file con key ~\n"
  read -p "Ottieni key (key32 or key64  or ... ) prima di contiunare, [ENTER] ..." tmp
  #workDir
  echo "Inserisci il percorso del file/directory (.locked)
[SOLO SE E' UN FILE ANCHE ESTENSIONE .locked dopo il 'nome_file.estensione_originale']"
  echo ""
  read -p "[file\dir]> " file
  echo "Inserisci il nome della tua key"
  read -p "[key]> " key
  echo ""
  start=$(date +%s.%N)
  core=$(python pyLock.py -p $key -u $file)
  end=$(date +%s.%N)
  runtime=$(python -c "print(${end} - ${start})")
  echo "Tempo impiegato per decifrare = $runtime [secondi]"
  echo ""
  #workDir
  echo -e "==> Il tuo file è stato decodifciato con successo! (con key '$key')"
  sleep
}

function info() {
echo -e "
 by @Frances_Ski                                                        V. 2.1.2

 Questo programma vuole essere di base per simulare,o fare un attacco Ransomware

 Il codice è in progressivo aggiornamento e miglioramento con techinche e metodi
 di crittografia più complessi e difficili da decifrare con attacchi BruteForce."
}

function __main__() {
  clear
  echo -e "
***************************************************************************************
||########################################||                                          *
||######## ENCRYPTER / DECRYPTER #########||                                          *
||########################################||          Per le opzioni 1 e 2            *
                                               ---------------------------------------*
> [1] => Encrypt file/dir Password Manuale <=| | Imposta prima la password usando:   |*
> [2] => Decrypt file/dir Password Manuale <=| | pyhton3 pyLock.py oppure digita 'p' |*
  ----------------------------------------     | (password di default = pippo)       |*
  ----------------------------------------     ---------------------------------------*
> [3] => Encrypt file/dir Con Key File                                                *
> [4] => Decrypt file/dir con Key File                                                *
                                                                                      *
> [p] => Genera Password Personale                                                    *
                                                                                      *
> [key32]  => Genera key 32  bits                                                     *
> [key64]  => Genera key 64  bits   <- (12.000 anni per trovarla con un BruteForce)   *
> [key128] => Genera key 128 bits                                                     *
> [key256] => Genera key 256 bits                                                     *
                                                                                      *
> [list]   => Mostra directory corrente                                               *
                                                                                      *
> [CTRL + C] => Esci                                                                  *
                                                                                      *
> [info] => Credit & Version                                                          *
                                                                                      *
# INSERIMENTO_PATH!!: Il percorso va inserito dalla directory di root:                *
  Es: /home/.../.../'nome_file.estensione' OPPURE /home/.../.../'nome_directory'      *
                                                                                ^     *
                                                     (non serve lo / alla fine) ^     *
______________________________________________________________________________________*
//||--------------------------------------------------------------------------------||*
//|| - NB: se non hai ancora una key, generala (key32 - key64 - key128 - key256)    ||*
//|| - Attenzione!! Se provi a usare una chiave non corretta il file verrà corrotto ||*
//||--------------------------------------------------------------------------------||*
***************************************************************************************
"

  read -p "[input]> " input

  case $input in
  1)
    encryptWithoutKey
    ;;
  2)
    decryptWithoutKey
    ;;
  3)
    encryptWithKey
    ;;
  4)
    decryptWithKey
    ;;
  "key32")
    key32
    ;;
  "key64")
    key64
    ;;
  "key128")
    key128
    ;;
  "key256")
    key256
    ;;
  "p")
    password
    ;;
  "list")
    workDir
    ;;
  "info")
    info
    sleep
    ;;
  esac
}

while [ true ]; do
  __main__
done
