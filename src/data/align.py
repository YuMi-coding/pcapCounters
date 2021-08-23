# Align data according to keys
from . import helpers
from typing import Iterable

class Align():
    def __init__(self, key = None, value = None, grain = 1):
        self.key = []
        self.value = []
        self.grain = grain
        if key is not None and value is not None:
            self.loadKeyValue(key, value)

    def loadKeyValue(self, key, value):
        assert len(key) == len(value), "The length of key and value must be the same."

        key = helpers.preprocess_keys(key) # Align the keys to the floored grain

        zipped = zip(key, value)
        zipped_sorted = sorted(zipped, key=lambda x: x[0])
        s_key, s_value = zip(*zipped_sorted)

        if len(self.key) <= 0 and len(self.value) <= 0:
            self.key.extend(list(s_key))
            self.value.extend(list(s_value))
            return self

        loaded_values = len(self.value[0]) if isinstance(self.value[0], Iterable) else 1
        pointer_1 = 0
        pointer_2 = 0
        new_key = []
        new_values = []
        while pointer_1 < len(self.key) and pointer_2 < len(s_key):
            if self.key[pointer_1] < s_key[pointer_2]:
                new_key.append(self.key[pointer_1])
                temp_list = list(self.value[pointer_1]) if isinstance(self.value[pointer_1], Iterable) else [self.value[pointer_1]]
                temp_list.append(0)
                new_values.append(tuple(temp_list))
                pointer_1 += 1
            elif self.key[pointer_1] == s_key[pointer_2]:
                new_key.append(self.key[pointer_1])
                temp_list = list(self.value[pointer_1]) if isinstance(self.value[pointer_1], Iterable) else [self.value[pointer_1]]
                temp_list.extend(s_value[pointer_2] if isinstance(s_value[pointer_2], Iterable) else [s_value[pointer_2]])
                new_values.append(tuple(temp_list))
                pointer_1 += 1
                pointer_2 += 1
            elif self.key[pointer_1] > s_key[pointer_2]:
                new_key.append(s_key[pointer_1])
                temp_list = [0] * loaded_values
                temp_list.append(s_value[pointer_2])
                new_values.append(tuple(temp_list))
                pointer_2 += 1

        self.key = new_key
        self.value = new_values
        return self

    def getDivided(self):

        assert isinstance(self.value[0],Iterable) and len(self.value[0]) == 2, "Value error, not dividable"

        divided_keys = []
        divided_values = []
        for i in range(len(self.key)):
            v1, v2 = self.value[i]
            v1 = float(v1)
            v2 = float(v2)
            if v1 == 0 or v2 == 0:
                continue
            divided_keys.append(self.key[i])
            divided_values.append(v1/v2)

        return Align(key=divided_keys, value=divided_values)