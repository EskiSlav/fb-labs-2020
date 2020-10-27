from typing import List, Dict, Tuple, IO, Any
from sys import stdout
from collections import Counter
import logging

sh = logging.StreamHandler(stdout)
fh = logging.FileHandler('report.txt', 'w') 
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=(sh, fh))

ciphertext_f = open('./cp_2/kozachok-fb82_kuznetsov-fb82_cp_2/ciphertext.txt', 'w')
myopentext_f = open('./cp_2/kozachok-fb82_kuznetsov-fb82_cp_2/myopentext.txt', 'r')


class Vigenere():

    letters = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    
    l_n = { letter: number for number, letter in enumerate(letters) }
    n_l = { number: letter for number, letter in enumerate(letters) }

    def __init__(self, text: str=None, f: IO[Any]=None, key: str=None):
        self.key = key
        self.text = text
        self.f = f

    def check_crypt(self) -> bool:
        if self.text is None and self.f is None:
            logging.info("Pass only file or only text")
            return False
        
        if self.key is None:
            logging.info("Decryption/Encryption only can be performed when key is not NONE") 
            return False
        return True

    def check_crack(self) -> bool:
        return True
    
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
                self.text = self.filter_text(self.f.read())
            except AttributeError:
                logging.error("Instead of filetype was passed another type")
                return ""

        self.text = self.text.lower()

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
        if not self.check_crypt():
            logging.info("Encryption cannot be performed")

        return self.__proc_text('e')

    def decrypt(self) -> str:
        if not self.check_crypt():
            logging.info("Decryption cannot be performed")

        return self.__proc_text('d')

    def crack(self) -> str:
        if not self.check_crack():
            return
        
        self.text = self.filter_text(self.text)

        Indices = []
        # Y = []

        # for r in [2,3,4,5,10,11,12,13,14,15,16,17,18,19,20]:
        #     Y = []
        #     for i in range(r+1):
        #         Y.append([])
        #         for letter in range(i, len(self.text), r):
        #             Y[i].append(letter)
        for r in [2,3,4,5,10,11,12,13,14,15,16,17,18,19,20]:
            Y =  self.text[::r] 
            letter_number = Counter(Y)
            summ = 0
            for letter, number in letter_number.items():
                summ += number * (number - 1)
                l = len(Y)
                I = summ / (l * (l - 1))
                Indices.append(I) # Append I
                print("Letter {letter}: {r} : {I}".format(letter=letter, r=r, I=I) )

        logging.info("Pass more text to get more accurate result")



        
if __name__ == '__main__':
    # ve_obj = Vigenere(f=myopentext_f, key="сашалюбитславика")
    # ciphertext = ve_obj.encrypt()
    # vd_obj = Vigenere(ciphertext, key='сашалюбитславика')
    # cleartext = vd_obj.decrypt()

    ve_obj = Vigenere(myopentext_f.read())
    ve_obj.crack()
  


    
    