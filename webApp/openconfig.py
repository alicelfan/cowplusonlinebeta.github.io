#CONFIG_PATH = "C:\cowplusonlinebeta.github.io\webApp\webApp\config.txt"
CONFIG_PATH = 'C:\cowplus_online\cowplusonlinebeta.github.io\webApp\config.txt'
def read_config():
    config = {}
    with open(CONFIG_PATH, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')
            config[key] = value
    return config

config = read_config()