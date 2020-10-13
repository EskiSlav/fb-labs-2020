from typing import List, Dict, Tuple, IO, Any
from sys import stdout
import logging

sh = logging.StreamHandler(stdout)
fh = logging.FileHandler('report.txt', 'w') 
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=(sh, fh))

# ciphertext = open('ciphertext.txt', 'w')
# myopentext = open('myopentext.txt', 'r')


class Vigenere():

    letters = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    l_n = { letter: number for number, letter in enumerate(letters) }
    n_l = { number: letter for number, letter in enumerate(letters) }

    def __init__(self, text: str=None, f: IO[Any]=None, key: str=None):
        self.key = key
        self.text = self.filter_text(text)
        self.file = f

    def check(self) -> bool:
        if self.text is None and self.file is None:
            logging.info("Pass only file or only text")
            return False
        
        # if not self.mode == 'e' or not self.mode == 'd':
        #     logging.info("Mode can be only 'e'(encrypt) or 'd'(decrypt)")
        #     return False
        
        if self.key is None:
            logging.info("Decryption/Encryption only can be performed when key is not NONE") 
            return False
        return True


    # @property
    # def filtered_cleartext(self):
    #     if self.mode == 'e' and not self.cleartext is None:
    #         self.cleartext = self.cleartext.lower()
    #         return self.filter_text(self.cleartext)
    #     return None

    # @property
    # def filtered_ciphertext(self):
    #     if self.mode == 'd' and not self.ciphertext is None:
    #         self.ciphertext = self.ciphertext.lower()
    #         return self.filter_text(self.ciphertext)
    #     return None

    # @property
    # def enc_cleartext(self):
    #     if self.mode == 'e' and not self.filtered_cleartext is None:
    #         return self.encrypt(self.filtered_cleartext, self.key)
    #     else:
    #         return None

    # @property
    # def dec_ciphertext(self):
    #     if self.mode == 'd' and not self.filtered_ciphertext is None:
    #         return self.decrypt(self.filtered_ciphertext, self.key)
    #     else:
    #         return None

    
    @staticmethod
    def filter_text(text: str) -> str:
        filtered_letters = []

        for letter in text:
            if letter in Vigenere.letters:
                filtered_letters.append(letter)

        return "".join(filtered_letters)

    def __proc_text(self, mode: str) -> str:
        n_l = Vigenere.n_l
        l_n = Vigenere.l_n
        processed_text_list = []
        key_len = len(self.key)
        
        if self.text is None:
            try:
                self.text = f.read()
            except AttributeError:
                logging.error("Insted of filetype was passed another type")
                return ""


        if mode == 'e':
            for i, letter in enumerate(self.text):
                letter_number = (l_n[letter] + l_n[self.key[i % key_len]]) % len(Vigenere.letters)
                processed_text_list.append(n_l[letter_number])
            
        else:
            for i, letter in enumerate(self.text):
                letter_number = (l_n[letter] - l_n[self.key[i % key_len]]) % len(Vigenere.letters)
                processed_text_list.append(n_l[letter_number])

        return "".join(processed_text_list)


    def encrypt(self) -> str:
        if not self.check():
            logging.info("Encryption cannot be performed")

        return self.__proc_text('e')

    def decrypt(self) -> str:
        if not self.check():
            logging.info("Decryption cannot be performed")

        return self.__proc_text('d')


    


if __name__ == '__main__':
    ve_obj = Vigenere('славиклюбитсашу', key="сашалюбитславика")
    ciphertext = ve_obj.encrypt()
    vd_obj = Vigenere('глшвфимжуъюсвбю', key='сашалюбитславика')
    cleartext = vd_obj.decrypt()
    print(f"{ciphertext=}\n{cleartext=}")
  


    
    