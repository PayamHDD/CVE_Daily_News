import Core.telegram
import Core.tenable
import Core.logger
import Core.nvd

from dotenv import load_dotenv
from os import getenv
def main():
    pass


if __name__ == "__main__":
    # Load environment variables
    
    # Load logging structure
    logger = logging.getLogger("TeleBot")
    log_format = logging.Formatter("%(asctime)s - %(funcName)s: %(message)s")
    log_level = logger.setLevel(logging.DEBUG)

    file_handler = handlers.RotatingFileHandler("TeleBot.log", mode = "a", maxBytes = 5242880, backupCount = 5)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_format)
    logger.addHandler(file_handler)

    file_handler = handlers.RotatingFileHandler("Error.log", mode = "a", maxBytes = 5242880, backupCount = 5)
    file_handler.setLevel(logging.ERROR)
    file_handler.setFormatter(log_format)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.ERROR)
    stream_handler.setFormatter(log_format)
    logger.addHandler(stream_handler) 
    # Start main
    main()
    