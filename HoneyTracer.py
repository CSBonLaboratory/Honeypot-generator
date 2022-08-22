from inotify_simple import INotify, flags


class HoneyTracer(object):
    _instance = None
    def __new__(cls):
        if cls._instance == None:
            cls._instance = super(HoneyTracer, cls).__new__(cls)
            
            cls.notifier = INotify()

            cls.commandFile = open("newContainer.txt","rt")

            cls.commandWatch = cls.notifier.add_watch("newContainer.txt",flags.MODIFY)

        
        return cls._instance

    def addTarget(self, targetPath : str):

        addWatch = self.notifier.add_watch(targetPath, flags.MODIFY)

        print("ADDED " + targetPath + "with wd: "+str(addWatch))

        return addWatch

    def removeTarget(self, targetWd):

        self.notifier.rm_watch(targetWd)

        print("REMOVED " + targetWd)

        return

    def waitEvent(self):
        while True:
            for event in self.notifier.read():
                print(event)

                if event.wd == self.commandWatch and event.mask & flags.MODIFY:
                    print('CLOSING HONEYPOT')
                    self.notifier.rm_watch(self.commandWatch)
                    self.commandFile.close()
                    return None

                return event.wd
        

def main():

    tracer = HoneyTracer()

    tracer.waitEvent()

if __name__ == "__main__":
    main()