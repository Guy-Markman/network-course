# -*- coding: utf-8 -*-
## @package multicast_chat.base Base module.
## @file base.py Implementation of @ref multicast_chat.base
#


import logging


## Base of all objects.
#
class Base(object):

    ## Log prefix to use.
    LOG_PREFIX = 'my'

    ## Logger.
    @property
    def logger(self):
        return self._logger

    ## Contructor.
    def __init__(self):
        self._logger = logging.getLogger(
            '%s.%s' % (
                self.LOG_PREFIX,
                self.__module__,
            ),
        )


## Setup logging system.
# @returns (logger) program logger.
#
def setup_logging(stream=None, level=logging.INFO):
    logger = logging.getLogger(Base.LOG_PREFIX)
    logger.propagate = False
    logger.setLevel(level)

    try:
        if stream is not None:
            h = logging.StreamHandler(stream)
            h.setLevel(logging.DEBUG)
            h.setFormatter(
                logging.Formatter(
                    fmt=(
                        '%(asctime)-15s '
                        '[%(levelname)-7s] '
                        '%(name)s::%(funcName)s:%(lineno)d '
                        '%(message)s'
                    ),
                ),
            )
            logger.addHandler(h)
    except IOError:
        logging.warning('Cannot initialize logging', exc_info=True)

    return logger
