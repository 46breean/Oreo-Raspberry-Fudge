from abc import ABC, abstractmethod

class AbstractSchool(ABC):
    def __init__(self):
        self.hi = "hello"
        print(self.hi)
        pass

    @abstractmethod
    def userRegistration(self, user):
        pass

class User:
    def xyz(self, school: AbstractSchool):
        school.userRegistration()

class School(AbstractSchool):
    def __init__(self):
        super().__init__()
        print("bye")

    def userRegistration(self, user):
        print("user registered")


School().userRegistration("hifhaifhi")