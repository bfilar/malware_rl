#!/usr/bin/python
"""
Defines the MalConv architecture.
Adapted from https://arxiv.org/pdf/1710.09435.pdf
Things different about our implementation and that of the original paper:
 * The paper uses batch_size = 256 and
   SGD(lr=0.01, momentum=0.9, decay=UNDISCLOSED, nesterov=True )
 * The paper didn't have a special EOF symbol
 * The paper allowed for up to 2MB malware sizes,
   we use 1.0MB because of memory on a Titan X
 """
import os
import sys

import numpy as np
import tensorflow as tf
from keras import metrics
from keras.models import load_model
from keras.optimizers import SGD

module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
model_path = os.path.join(module_path, "malconv.h5")

tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)


class MalConv:
    def __init__(self):
        self.batch_size = 100
        self.input_dim = 257  # every byte plus a special padding symbol
        self.padding_char = 256
        self.malicious_threshold = 0.5

        self.model = load_model(model_path)
        _, self.maxlen, self.embedding_size = self.model.layers[1].output_shape

        self.model.compile(
            loss="binary_crossentropy",
            optimizer=SGD(lr=0.01, momentum=0.9, nesterov=True, decay=1e-3),
            metrics=[metrics.binary_accuracy],
        )

    def extract(self, bytez):
        b = np.ones((self.maxlen,), dtype=np.int16) * self.padding_char
        bytez = np.frombuffer(bytez[: self.maxlen], dtype=np.uint8)
        b[: len(bytez)] = bytez
        return b

    def predict_sample(self, bytez):
        return self.model.predict(bytez.reshape(1, -1))[0][0]
