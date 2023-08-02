#!/usr/local/bin/python3
# encoding: utf-8

class RoundTripTime(object):
    def __init__(self, milliseconds):
        self.value = milliseconds

    def __str__(self):
        return '{:f}'.format(self.value)
        
    def __format__(self, __format_spec):
        return __format_spec.format(self.value)
    
    def __neg__(self):
        return RoundTripTime(-self.value)

    def __abs__(self):
        return RoundTripTime(abs(self.value))
    
    def __add__(self, other):
        if isinstance(other, (int, float)):
            return RoundTripTime(self.value + other)
        elif isinstance(other, (RoundTripTime, )):
            return RoundTripTime(self.value + other.value)
        raise TypeError()

    def __sub__(self, other):
        return self + -other
    
    def __mul__(self, other):
        if isinstance(other, (int, float)):
            return RoundTripTime(self.value * other)
        raise TypeError()
    
    def __eq__(self, other):
        if isinstance(other, (int, float)):
            return self.value == other
        elif isinstance(other, (RoundTripTime, )):
            return self.value == other.value
        raise TypeError()

    def __lt__(self, other):
        if isinstance(other, (int, float)):
            return self.value < other
        elif isinstance(other, (RoundTripTime, )):
            return self.value < other.value
        raise TypeError()

    def __le__(self, other):
        return self < other or self == other

    def __gt__(self, other):
        if isinstance(other, (int, float)):
            return self.value > other
        elif isinstance(other, (RoundTripTime, )):
            return self.value > other.value
        raise TypeError()

    def __ge__(self, other):
        return self > other or self == other
    
    @property
    def seconds(self):
        return self.value / 1000.0
    s = seconds
        
    @property
    def milliseconds(self):
        return self.value
    ms = milliseconds
    
    @property
    def microseconds(self):
        return self.value * 1000.0
    ns = microseconds
