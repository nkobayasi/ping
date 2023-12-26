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
    
    def __pos__(self):
        return RoundTripTime(+self.value)

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
    
    def __cmp__(self, other):
        if isinstance(other, (int, float)):
            return self.value - other
        elif isinstance(other, (RoundTripTime, )):
            return self.value - other.value
        raise TypeError()
    
    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __le__(self, other):
        return self < other or self == other

    def __gt__(self, other):
        return self.__cmp__(other) > 0

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

def covariance(x, y):
    _ = []
    x_mean = statistics.mean(x)
    y_mean = statistics.mean(y)
    for xi, yi in zip(x, y):
        _.append((xi - x_mean) * (yi - y_mean))
    return statistics.mean(_)

def least_squares_method(x, y):
    A = covariance(x, y) / statistics.variance(x)
    B = statistics.mean(y) - A * statistics.mean(x)
    return A, B

def r2_score(x, y, A, B):
    p = 0
    t = 0
    y_mean = statistics.mean(y)
    for xi, yi in zip(x, y):
        ypi = A * xi + B
        p += (yi - ypi) ** 2
        t += (yi - y_mean) ** 2
    return 1 - p / t

def main():
    rtt = RoundTripTime(microseconds=1000.0)
    print('{:f}'.format(rtt))
    print(rtt)
    print(rtt.seconds)
    print(rtt + RoundTripTime(seconds=1.0))
    print(RoundTripTime(microseconds=900.0))

if __name__ == '__main__':
    main()