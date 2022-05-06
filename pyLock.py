'''
Encrypt e Decrypt i file utilizzando la crittografia AES e una password comune.
Puoi usarlo per bloccare i file prima che vengano caricati su servizi di archiviazione
come DropBox o Google Drive.

La password può essere archiviata in un file sicuro, specificato sulla riga di comando
oppure può essere immessa manualmente ogni volta che viene eseguito lo strumento.

Ecco come utilizzare questo strumento per crittografare un numero di file utilizzando
un file locale e sicuro. È possibile opzionalmente specificare l'opzione --lock
ma poiché è l'impostazione predefinita, non è necessario.

   $ lock_files.py file1.txt file2.txt dir1 dir2
   Password: secret
   Re-enter password: secret

Al termine del comando di blocco, tutti i file verranno bloccati (encrypted,
con l'estensione ".locked").

Puoi bloccare gli stessi file più volte con password diverse.
Ogni volta che lock_files.py viene eseguito in modalità di blocco,
viene aggiunta un'altra estensione ".locked". Ogni volta che viene
eseguito in modalità di sblocco, viene rimossa un'estensione ".locked".
La modalità di sblocco viene abilitata specificando l'opzione --unlock.

Naturalmente, inserire la password manualmente ogni volta può essere una rischioso.
Normalmente è più facile creare un file di sola lettura che può essere riutilizzato.
Ecco come fare:

   $ cat >password-file
   thisismysecretpassword
   EOF
   $ chmod 0600 password-file

Ora puoi utilizzare il file della password in questo modo per bloccare e sbloccare un file.

   $ lock_files.py -p password-file file1.txt
   $ lock_files.py -p password-file --unlock file1.txt.locked

In modalità di Decrypt, lo strumento esplora i file e le directory specificati alla ricerca
di file con estensione .locked e li sblocca (decodifica).

Ecco come utilizzare questo strumento per decrittografare un file,
eseguire un programma e quindi crittografarlo nuovamente quando il programma termina.


   $ # the unlock operation removes the .locked extension
   $ lock_files.py -p ./password --unlock file1.txt.locked
   $ edit file1.txt
   $ lock_files.py -p ./password file1.txt

Lo strumento controlla ogni file per assicurarsi che sia scrivibile prima dell'elaborazione.
Se qualche file non è scrivibile, il programma segnala un errore ed esce a meno che non specifichi --warn,
nel qual caso segnala un avviso che il file verrà ignorato e continuerà.

Se si desidera crittografare e decrittografare i file in modo che possano essere elaborati utilizzando openssl,
è necessario utilizzare la modalità di compatibilità (-c).

Ecco come puoi crittografare un file usando lock_files.py e decrittografarlo usando openssl.

   $ lock_files.py -P secret --lock file1.txt
   $ ls file1*
   file1.txt.locked
   $ openssl enc -aes-256-cbc -d -a -salt -pass pass:secret -in file1.txt.locked -out file1.txt

Ecco come puoi crittografare un file usando openssl e poi
decifralo usando lock_files.py.

   $ openssl enc -aes-256-cbc -e -a -salt -pass pass:secret -in file1.txt -out file1.txt.locked
   $ ls file1*
   file1.txt      file1.txt.locked
   $ lock_files.py -c -W -P secret --unlock file1.txt.locked
   $ ls file1*
   file1.txt

NOTA: è necessario utilizzare l'opzione -W per modificare gli errori in avviso poiché il file di output file1.txt esiste già.
'''
import argparse
import base64
import getpass
import inspect
import multiprocessing
import os
import subprocess
import sys
import threading
from threading import Thread, Lock, Semaphore
import tqdm

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError as exc:
    print('ERROR: Import fallita!, digita come root "pip3 install cryptography".\n{:>7}{}'.format('', exc))
    sys.exit(1)

try:
    import Queue as queue  # python 2
except ImportError:
    import queue   # python3

#-----------------------------------------------------------------------------------------
# =======================                                                                |
# Variabili d'ambiente. |                                                                |
# =======================                                                                |
VERSION = '2.1.2'                                                                       #|
th_mutex = Lock()       # mutex per thread IO                                            |
th_semaphore = None     # semaforo per limitare il numero massimo di thread attivi       |
th_abort = False        # Se vero, interrompi tutti i thread                             |
#-----------------------------------------------------------------------------------------
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

# =========
# Classi. |
# =========
class AESCipher:
    # Encrypt o Decrypt strnghe o files.
    def __init__(self, openssl=False, digest='md5', keylen=32, ivlen=16):
        '''
        Inizializzazione Oggetto

        @param openssl  Funziona in modo identico a openssl.
        @param digest   Il digest utilizzato.
        @param keylen   Lunghezza della key (32-256, 16-128, 8-64).
        @param ivlen    Lunghezza del vettore di inizializzazione.
        '''
        self.m_openssl = openssl
        self.m_openssl_prefix = b'Salted__'
        self.m_openssl_prefix_len = len(self.m_openssl_prefix)
        self.m_digest = getattr(__import__('hashlib', fromlist=[digest]), digest)
        self.m_keylen = keylen
        self.m_ivlen = ivlen
        if keylen not in [8, 16, 32]:
            err('invalid keylen {}, must be 8, 16 or 32'.format(keylen))
        if openssl and ivlen != 16:
            err('invalid ivlen size {}, for openssl compatibility it must be 16'.format(ivlen))

    def encrypt(self, password, plaintext):
        '''
        Encrypt il testo in chiaro utilizzando la password, opzionalmente
        utilizzando un algoritmo di crittografia compatibile con openssl.

        Se viene eseguito in modalità compatibilità openssl, è lo stesso
        che eseguire openssl in questo modo:

            $ openssl enc -aes-256-cbc -e -a -salt -pass pass:<password> -in plaintext

        @param password  The password.
        @param plaintext The plaintext to encrypt.

        '''
        # Setup key e IV
        if self.m_openssl:
            salt = os.urandom(self.m_ivlen - len(self.m_openssl_prefix))
            key, iv = self._get_key_and_iv(password, salt)
            if key is None or iv is None:
                return None
        else:
            # No 'Salted__' prefix.
            key = self._get_password_key(password)
            iv = os.urandom(self.m_ivlen)  # IV è uguale alla dimensione del blocco per la modalità CBC
        # Key
        key = self._encode(key)

        # Encrypt
        padded_plaintext = self._pkcs7_pad(plaintext, self.m_ivlen)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext_binary = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Finalizzazione
        if self.m_openssl:
            # openssl compatibile.
            openssl_compatible = self.m_openssl_prefix + salt + ciphertext_binary
            ciphertext = base64.b64encode(openssl_compatible)
        else:
            ciphertext = base64.b64encode(iv + ciphertext_binary)

        return ciphertext

    def decrypt(self, password, ciphertext):
        '''
        Decrittografare il testo cifrato utilizzando la password,
        opzionalmente utilizzando un algoritmo di decrittografia compatibile con openssl.

        Se è stato crittografato in modalità compatibile con openssl,
        è come eseguire il seguente comando di decrittazione openssl:

            $ egrep -v '^#|^$' | openssl enc -aes-256-cbc -d -a -salt -pass pass:<password> -in ciphertext

        @param password     password.
        @param ciphertext   ciphertext -> decrypt.
        @returns            decrypted file.
        '''
        if self.m_openssl:
            # Base64 decode
            ciphertext_prefixed_binary = base64.b64decode(ciphertext)
            if ciphertext_prefixed_binary[:self.m_openssl_prefix_len] != self.m_openssl_prefix:
                err('bad header, cannot decrypt')
            salt = ciphertext_prefixed_binary[self.m_openssl_prefix_len:self.m_ivlen]  # prendi il salt

            # Creazione della key e IV.
            key, iv = self._get_key_and_iv(password, salt)
            if key is None or iv is None:
                return None
        else:
            key = self._get_password_key(password)
            ciphertext_prefixed_binary = base64.b64decode(ciphertext)
            iv = ciphertext_prefixed_binary[:self.m_ivlen]  # IV è uguale alla dimensione del blocco per la modalità CBC

        # Key
        key = self._encode(key)

        # Decrypt
        ciphertext_binary = ciphertext_prefixed_binary[self.m_ivlen:]
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext  = decryptor.update(ciphertext_binary) + decryptor.finalize()
        plaintext = self._pkcs7_unpad(padded_plaintext)
        return plaintext

    def _get_password_key(self, password):
        '''
        Inserisci la password se necessario.
        Questo viene utilizzato per Encrypt & Decrypt.
        '''
        if len(password) >= self.m_keylen:
            key = password[:self.m_keylen]
        else:
            key = self._pkcs7_pad(password, self.m_keylen)
        return key

    def _get_key_and_iv(self, password, salt):
        '''
        Ricavare la chiave e l'IV dalla password e dal salt.

        @param password  La password da utilizzare come origine.
        @param salt      Il salt.
        '''
        try:
            password = password.encode('utf-8', 'ignore')
            #                                      ^
            # Ignore va bene qui perché sarà simmetrico per entrambe le operazioni di crittografia e decrittografia.
            maxlen = self.m_keylen + self.m_ivlen
            keyiv = self.m_digest(password + salt).digest()
            digest = keyiv
            while len(keyiv) < maxlen:
                digest = self.m_digest(digest + password + salt).digest()
                keyiv += digest  # aggiungi gli ulitmi 16 bytes
            key = keyiv[:self.m_keylen]
            iv = keyiv[self.m_keylen:self.m_keylen + self.m_ivlen]
            return key, iv
        except UnicodeDecodeError as exc:
            err('Fallimento Generazione Key e IV: {}'.format(exc))
            return None, None

    def _encode(self, val):
        # Encode string
        if isinstance(val, str):
            try:
                val = val.encode('utf-8')
            except UnicodeDecodeError:
                pass  # python 2, don't care
        return val

    def _pkcs7_pad(self, text, size):
        '''
        PKCS#7.

        Riempi fino al limite usando un valore di byte che indica il numero di byte riempiti
        per facilitare l'annullamento del riempimento in un secondo momento.

        @param text  Il testo da riempire
        @param size  TLa dimensione del blocco
        '''
        num_bytes = size - (len(text) % size)

        if isinstance(text, str):
            text += chr(num_bytes) * num_bytes
        elif isinstance(text, bytes):
            text += bytearray([num_bytes] * num_bytes)
        else:
            assert False
        return text

    def _pkcs7_unpad(self, padded):
        '''
        Abbiamo riempito con il numero di caratteri da rimuovere.
        Basta prenderlo e troncare la stringa.
        '''
        if isinstance(padded, str):
            unpadded_len = ord(padded[-1])
        elif isinstance(padded, bytes):
            unpadded_len = padded[-1]
        else:
            assert False
        return padded[:-unpadded_len]

#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

# ===========================
# Messaggi Utilità Funzioni |
# ===========================

def _msg(prefix, msg, level, ofp):
    #Segnalazione di messaggi thread-safe.
    th_mutex.acquire()
    try:
        ofp.write('{}:{} {}\n'.format(prefix, inspect.stack()[level][2], msg))
    finally:
        th_mutex.release()


def info(msg, level=1, ofp=sys.stdout):
    # Visualizza un semplice messaggio informativo con informazioni di contesto.
    _msg('INFO', msg, level+1, ofp)


# Visualizza un semplice messaggio informativo con informazioni di contesto.
def infov(opts, msg, level=1, ofp=sys.stdout):
    if opts.verbose:
        _msg('INFO', msg, level+1, ofp)

def infov2(opts, msg, level=1, ofp=sys.stdout):
    if opts.verbose > 1:
        _msg('INFO', msg, level+1, ofp)


def err(msg, level=1, ofp=sys.stdout):
    # Visualizza il messaggio di errore con le informazioni sul contesto ed esci.
    _msg('ERROR', msg, level+1, ofp)
    abort_threads()
    sys.exit(1)


def errn(msg, level=1, ofp=sys.stdout):
    # Visualizza il messaggio di errore con le informazioni sul contesto ma non esce.
    _msg('ERROR', msg, level+1, ofp)


def warn(msg, level=1, ofp=sys.stdout):
    # Visualizza il messaggio di errore con le informazioni sul contesto ma non esce.
    _msg('WARNING', msg, level+1, ofp)


def _println(msg, ofp=sys.stdout):
    # Stampa il msh nella nuova linea
    th_mutex.acquire()
    try:
        ofp.write(msg + '\n')
    finally:
        th_mutex.release()


#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

# =================
# Thread utility. |
# =================
def abort_threads():
    # Imposta flag di uscita
    th_mutex.acquire()
    try:
        global th_abort
        th_abort = True
    finally:
        th_mutex.release()


def get_num_cores():

    if os.name == 'posix':
        # dovrebbe essere possibile lanciare getconf.
        try:
            out = subprocess.check_output('getconf _NPROCESSORS_CONF', stderr=subprocess.STDOUT, shell=True)
            return int(out.strip())
        except subprocess.CallProcessError as exc:
            err('command failed: {}'.format(exc))

    return multiprocessing.cpu_count()


def thread_process_file(opts, password, entry, stats):
    '''
    Thread funzionalità.
    Aspetta il semaforo prima di eseguire
    '''
    if th_abort is False:
        with th_semaphore:
            process_file(opts, password, entry, stats)


def wait_for_threads():
    for th in threading.enumerate():
        if th == threading.current_thread():
            continue
        th.join()

#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

# ======================
# Funzioni SPecifiche. |
# ======================
def get_err_fct(opts):
    # Ottieni info dalla function: error o warning dipendono da --warn nelle impostazioni.
    if opts.warn is True:
        return warn
    return err


def stat_inc(stats, key, value=1):
    th_mutex.acquire()
    try:
        stats[key] += value
    finally:  # avoid deadlock from exception
        th_mutex.release()


def check_existence(opts, path):
    '''
    Vedi se il file esiste o no.
    Se -o oppure --overwrite è specificato, non serve di vedere se esiste.
    '''
    if opts.overwrite is False and os.path.exists(path):
        get_err_fct(opts)('il file esiste, non è possibile continuare: {}'.format(path))


def read_file(opts, path, stats):
    # Leggi il file
    try:
        with open(path, 'rb') as ifp:
            data = ifp.read()
            stat_inc(stats, 'read', len(data))
            return data
    except IOError as exc:
        get_err_fct(opts)('fallita lettura del file "{}": {}'.format(path, exc))
        return None


def write_file(opts, path, content, stats, width=0):
    # Scrivi il file
    try:
        with open(path, 'wb') as ofp:
            if width < 1:
                ofp.write(content)
            else:
                i = 0
                nl = '\n' if isinstance(content, str) else b'\n'
                while i < len(content):
                    ofp.write(content[i:i+width] + nl)
                    i += width
            stat_inc(stats, 'written', len(content))
    except IOError as exc:
        get_err_fct(opts)('faillita scrittura del file "{}": {}'.format(path, exc))
        return False
    return True


def lock_file(opts, password, path, stats):
    # Blocca il file
    out = path + opts.suffix
    infov2(opts, 'lock "{}" --> "{}"'.format(path, out))
    check_existence(opts, out)
    content = read_file(opts, path, stats)
    if content is not None:
        data = AESCipher(openssl=opts.openssl).encrypt(password, content)
        if data is not None and write_file(opts, out, data, stats, width=opts.wll) is True and th_abort is False:
            if out != path:
                os.remove(path)  # rimovi originale di input
            stat_inc(stats, 'locked')


def unlock_file(opts, password, path, stats):
    # Sblocca il file
    if path.endswith(opts.suffix):
        if len(opts.suffix) > 0:
            out = path[:-len(opts.suffix)]
        else:
            out = path
        infov2(opts, 'unlock "{}" --> "{}"'.format(path, out))
        check_existence(opts, out)
        content = read_file(opts, path, stats)
        if content is not None and th_abort is False:
            try:
                data = AESCipher(openssl=opts.openssl).decrypt(password, content)
                if write_file(opts, out, data, stats) is True:
                    if out != path:
                        os.remove(path)  # rimovi originale di input
                    stats['unlocked'] += 1
            except ValueError as exc:
                get_err_fct(opts)('operazione di unlock/decrypt fallita per "{}": {}'.format(path, exc))
    else:
        infov2(opts, 'skip "{}"'.format(path))
        stats['skipped'] += 1


def process_file(opts, password, path, stats):
    # Processa il file.
    if th_abort is False:
        stat_inc(stats, 'files')
        if opts.lock is True:
            lock_file(opts, password, path, stats)
        else:
            unlock_file(opts, password, path, stats)


def process_dir(opts, password, path, stats):
    # Processa la directory, SI PARTE DAL TOP-LEVEL.
    stats['dirs'] += 1
    if opts.recurse is True:
        # Funzione ricorsiva sui file.
        for root, subdirs, subfiles in os.walk(path):
            for subfile in sorted(subfiles, key=str.lower):
                if subfile.startswith('.'):
                    continue
                if th_abort is True:
                    break
                subpath = os.path.join(root, subfile)
                th = Thread(target=thread_process_file, args=(opts, password, subpath, stats))
                th.daemon = True
                th.start()
    else:
        # Uso di listdir() per prendere i file solo nella directory corrente.
        for entry in sorted(os.listdir(path), key=str.lower):
            if entry.startswith('.'):
                continue
            subpath = os.path.join(path, entry)
            if os.path.isfile(subpath):
                if th_abort is True:
                    break
                th = Thread(target=thread_process_file, args=(opts, password, subpath, stats))
                th.daemon = True
                th.start()


def process(opts, password, entry, stats):
    '''
    Processo in in ingresso.
    -> se è un file lavora solo su quello
    -> se è una direcoty uso di --recurse.
    '''
    if th_abort is False:
        if os.path.isfile(entry):
            th = Thread(target=thread_process_file, args=(opts, password, entry, stats))
            th.daemon = True
            th.start()
        elif os.path.isdir(entry):
            process_dir(opts, password, entry, stats)


def run(opts, password, stats):
    for entry in opts.FILES:
        process(opts, password, entry, stats)


def summary(opts, stats):
    if opts.verbose:
        action = 'lock' if opts.lock is True else 'unlock'
        print('')
        print('Setup')
        print('   action:              {:>12}'.format(action))
        print('   inplace:             {:>12}'.format(str(opts.inplace)))
        print('   jobs:                {:>12,}'.format(opts.jobs))
        print('   overwrite:           {:>12}'.format(str(opts.overwrite)))
        print('   suffix:              {:>12}'.format('"' + opts.suffix + '"'))
        print('')
        print('Summary')
        print('   total files:         {:>12,}'.format(stats['files']))
        if opts.lock:
            print('   total locked:        {:>12,}'.format(stats['locked']))
        if opts.unlock:
            print('   total unlocked:      {:>12,}'.format(stats['unlocked']))
        print('   total skipped:       {:>12,}'.format(stats['skipped']))
        print('   total bytes read:    {:>12,}'.format(stats['read']))
        print('   total bytes written: {:>12,}'.format(stats['written']))
        print('')


def get_password(opts):
    '''
    Ottieni la password.

    Se l'utente ha specificato -P o --password sulla riga di comando, usa quello.

    Se l'utente ha specificato -p <file> o --password-file <file> sulla riga di comando,
    leggere la prima riga del file che non è vuota o che inizia con #.

    NBB!! => Se nessuno dei precedenti, richiederlo all'utente due volte.
    '''
    if opts.password:
        return opts.password

    # l'utente specifica la password , di default dovrebbe essere 0600.
    if opts.password_file:
        if not os.path.exists(opts.password_file):
            err("il 'password file' non esiste: {}".format(opts.password_file))
        password = None
        with open(opts.password_file, 'rb') as ifp:
            for line in ifp.readlines():
                # spazio bianco iniziale e finale non consentito
                line = line.strip()
                # salta le righe vuote e di commento
                if line and line[0] != '#':
                    password = line
                    break
        if password is None:
            err('password non torvata nel file ' + opts.password_file)
        return password

    # User did not specify a password, prompt twice to make sure that
    # the password is specified correctly.
    password = getpass.getpass('Password: ')
    password2 = getpass.getpass('Re-enter password: ')
    if password != password2:
        err('le password non coincidono!')
    return password


def getopts():
    # Prendi i comandi dal terminale.
    def gettext(s):
        lookup = {
            'usage: ': 'USAGE:',
            'positional arguments': 'POSITIONAL ARGUMENTS',
            'optional arguments': 'OPTIONAL ARGUMENTS',
            'mostra msg di aiuto ed esci': 'mostra msg di aiuto ed esci.\n ',
        }
        return lookup.get(s, s)

    argparse._ = gettext
    base = os.path.basename(sys.argv[0])
    name = os.path.splitext(base)[0]
    usage = '\n  {0} [OPTIONS] [<FILES_OR_DIRS>]+'.format(base)
    desc = 'DESCRIPTION:{0}'.format('\n  '.join(__doc__.split('\n')))
    epilog = r'''EXAMPLES:
   # Esempio 1: help
   $ {0} -h

   # Esempio 2: lock/unlock a single file
   $ {0} -P 'secret' file.txt
   $ ls file.txt*
   file.txt.locked
   $ {0} -P 'secret' --unlock file.txt
   $ ls -1 file.txt*
   file.txt

   # Esempio 3: lock/unlock a set of directories
   $ {0} -P 'secret' project1 project2
   $ find project1 project2 --type f -name '*.locked'
   <output snipped>
   $ {0} -P 'secret' --unlock project1 project2

   # Esempio 4: lock/unlock using a custom extension
   $ {0} -P 'secret' -s .EncRypt file.txt
   $ ls file.txt*
   file.txt.EncRypt
   $ {0} -P 'secret' -s .EncRypt --unlock file.txt

   # Esempio 5: lock/unlock a file
   $ {0} -P 'secret' -i -l file.txt
   $ ls file.txt*
   file.txt
   $ {0} -P 'secret' -i -u file.txt
   $ ls file.txt*
   file.txt

   # Esempio 6: uso di un password file.
   $ echo 'secret' >pass.txt
   $ chmod 0600 pass.txt
   $ {0} -p pass.txt -l file.txt
   $ {0} -p pass.txt -u file.txt.locked

   # Esempio 7: encrypt e decrypt con openssl
   $ echo 'secret' >pass.txt
   $ chmod 0600 pass.txt
   $ {0} -p pass.txt -c -l file.txt
   $ openssl enc -aes-256-cbc -d -a -salt -pass file:pass.txt -in file.txt.locked
   $ {0} -p pass.txt -c -u file.txt.locked

 '''.format(base)
    afc = argparse.RawTextHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=afc,
                                     description=desc[:-2],
                                     usage=usage,
                                     epilog=epilog)

    group1 = parser.add_mutually_exclusive_group()

    parser.add_argument('-c', '--openssl',
                        action='store_true',
                        help='''Enable openssl compatibility.

   $ openssl enc -aes-256-cbc -d -a -salt -pass pass:PASSWORD -in FILE -o FILE.locked
   $ {0} -P PASSWORD -l FILE

 '''.format(base))

    parser.add_argument('-d', '--decrypt',
                        action='store_true',
                        help='''Unlock/decrypt files.
                        Stessa cosa che mettere --unlock. ''')

    parser.add_argument('-e', '--encrypt',
                        action='store_true',
                        help='''Lock/encrypt files.
                        Stessa cosa che mettere --lock and is the default. ''')

    parser.add_argument('-i', '--inplace',
                        action='store_true',
                        help='''In place mode.
                        Sovrascrivi nel posto.  ''')

    #nc = get_num_cores()
    parser.add_argument('-j', '--jobs',
                        action='store',
                        type=int,
                        default=1,
                        metavar=('NUM_THREADS'),
                        help='''Specify the maximum number of active threads.
                        Questa cosa fa comodo quando i file sono molto grandi di dimensioni (MB).
                        Default: %(default)s
                        ''')

    parser.add_argument('-l', '--lock',
                        action='store_true',
                        help='''Lock files.
                        I file sono bloccati con estensione ".locked" ''')

    parser.add_argument('-o', '--overwrite',
                        action='store_true',
                        help='''Sovrascrittra file che gia esiste. ''')

    group1.add_argument('-p', '--password-file',
                        action='store',
                        type=str,
                        help='''file che contiene la password. ''')

    group1.add_argument('-P', '--password',
                        action='store',
                        type=str,
                        help='''Specifica della password dal terminale. ''')

    parser.add_argument('-r', '--recurse',
                        action='store_true',
                        help='''Ricorsione nelle sub-direcotires. ''')

    parser.add_argument('-s', '--suffix',
                        action='store',
                        type=str,
                        default='.locked',
                        metavar=('EXTENSION'),
                        help='''Estensione specifica dei file bloccati.
                        Default: %(default)s ''')

    parser.add_argument('-u', '--unlock',
                        action='store_true',
                        help='''Unlock files.
                        File con estensione ".locked" vengono sbloccati ''')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='''Verbose Mode. ''')

    # Mostra versione
    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s version {0}'.format(VERSION),
                        help="""Mostra Versione del Programma. """)

    parser.add_argument('-w', '--wll',
                        action='store',
                        type=int,
                        default=72,
                        metavar=('INTEGER'),
                        help='''The width of each locked/encrypted line.
                        Questa cosa è imposrtante pe ri file che sono molto lunghi o grandi
                        Default: %(default)s ''')

    parser.add_argument('-W', '--warn',
                        action='store_true',
                        help='''Warning se l'azione di lock/Unlock fallisce. ''')

    # Positional arguments finali.
    parser.add_argument('FILES',
                        nargs="*",
                        help='files da elaborare')

    opts = parser.parse_args()

    # lock e unlock.
    if opts.decrypt is True:
        opts.unlock = True
    if opts.encrypt is True:
        opts.lock = True
    if opts.lock is True and opts.unlock is True:
        err('hai seleziononato la mutua esclusione per lock/encrypt e unlock/decrypt.')
    if opts.lock is False and opts.unlock is False:
        # default
        opts.lock = True
    if opts.inplace:
        opts.suffix = ''
        opts.overwrite = True
    elif opts.overwrite == True and opts.suffix == '':
        opts.inplace = True
    return opts


def main():
    # MAIN
    opts = getopts()
    password = get_password(opts)

    stats = {
        'locked': 0,
        'unlocked': 0,
        'skipped': 0,
        'files': 0,
        'dirs': 0,
        'read': 0,
        'written': 0,
        }

    # Utilizzare il mutex per l'I/O per evitare l'output intervallato.
    # Utilizzare il semaforo per limitare il numero di thread attivi.
    global th_semaphore
    th_semaphore = Semaphore(opts.jobs)

    try:
        run(opts, password, stats)
        wait_for_threads()
    except KeyboardInterrupt:
        abort_threads()
        _println('', sys.stderr)
        errn('^C rilevati, pulizia dei threads, attendi...\n')
        wait_for_threads()

    summary(opts, stats)
    if th_abort == True:
        sys.exit(1)


if __name__ == '__main__':
    main()
