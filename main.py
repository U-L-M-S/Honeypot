import logging as l
from logging.handlers import RotatingFileHandler


def main():
    funnel_logger = l.getLogger('FunnelLogger')
    funnel_logger.setLevel(l.INFO)

    logging_format = l.Formatter('%(message)s')

    funnel_handler = RotatingFileHandler('system_logs.log', maxBytes=2000, backupCount=5)
    funnel_handler.setFormatter(logging_format)
    
    funnel_logger.addHandler(funnel_handler)

#########

    creds_logger = l.getLogger('CredsLogger')
    creds_logger.setLevel(l.INFO)

    creds_handler = RotatingFileHandler('cmd_system_logs.log', maxBytes=2000, backupCount=5)
    creds_handler.setFormatter(logging_format)
    
    creds_logger.addHandler(creds_handler)