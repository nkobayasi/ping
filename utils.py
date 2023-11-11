#!/usr/local/bin/python3
# encoding: utf-8

class RoundTripTime(object):
    def __init__(self, milliseconds=None, seconds=None, microseconds=None):
        if milliseconds is not None:
            self.value = milliseconds
        elif seconds is not None:
            self.value = seconds * 1000.0
        elif microseconds is not None:
            self.value = microseconds / 1000.0
        else:
            raise ValueError()

    def __str__(self):
        if self.value < 1.0:
            return '<1ms'
        return '{:.1f}ms'.format(self.value)
        
    def __format__(self, __format_spec):
        return format(self.value, __format_spec)
    
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

    def __matmul__(self, other):
        raise NotImplemented()

    def __truediv__(self, other):
        raise NotImplemented()

    def __floordiv__(self, other):
        raise NotImplemented()

    def __mod__(self, other):
        raise NotImplemented()

    def __divmod__(self, other):
        raise NotImplemented()

    def __pow__(self, other, modulo=None):
        raise NotImplemented()
    
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

def main():
    rtt = RoundTripTime(microseconds=1000.0)
    print('{:f}'.format(rtt))
    print(rtt)
    print(rtt.seconds)
    print(rtt + RoundTripTime(seconds=1.0))
    print(RoundTripTime(microseconds=900.0))

if __name__ == '__main__':
    main()