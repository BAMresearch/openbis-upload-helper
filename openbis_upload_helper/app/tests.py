from django.test import TestCase

# Create your tests here.


def test_placeholder():
    assert True


class TestCaseClass(TestCase):
    def test_example(self):
        var_two = 2
        assert var_two == 1 + 1
