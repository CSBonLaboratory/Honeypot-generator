from OptionGenerator import OptionGenerator
from typing import Dict, List
from HoneyTree import HoneyLink, HoneyTree
import ipaddress

class HostOptionGenerator(OptionGenerator):

    NAME_IDX = 1
    SWI_IDX = 0

    def __init__(self, seed : int = 1, ip: int = 1, globalIp : str = '0.0.0.0', mask: int= 16):
        self.globalIp = globalIp
        self.mask = mask
        super().__init__()


    @OptionGenerator.registerOption('abstractLink', 'upperLinks')
    def genLinks(self, *args, **kwargs) -> List[List[HoneyLink]]:
        parentNode : HoneyTree = kwargs['parentNode']
        
        return parentNode.links


    @OptionGenerator.registerOption('node','name')
    def genNameContainer(self, *args, **kwargs) -> str:

        posStr = ''
        for pos in kwargs['nameHint']:
            posStr += f'_{pos}'
        res = "h" + posStr      

        return res
        

    @OptionGenerator.registerOption('virtualLink', 'params1')
    def genIp(self, *args, **kwargs) -> Dict:
        intIp = int(ipaddress.IPv4Address(self.globalIp))

        intIp = intIp + 1

        self.globalIp = ipaddress.ip_address(intIp).__str__()

        return {'ip' : self.globalIp + '/' + str(self.mask)}

    @OptionGenerator.registerOption('virtualLink', 'intfName1')
    def genIntfNameHost(self, *args, **kwargs)-> str:

        containerName : str = kwargs['containerName']
        abstractLinkGrade : int = kwargs['linkGrade']

        return containerName[3:] + str(abstractLinkGrade)

    @OptionGenerator.registerOption('node', 'dimage')
    def genImageDocker(self, *args, **kwargs) -> str:
        return 'honey:latest'

    @OptionGenerator.registerOption('node', 'dcmd')
    def genStartCommand(self, *args, **kwargs) -> str:
        return 'python app.py'

    @OptionGenerator.registerOption('switch', 'name')
    def genSwitchName(self, *args, **kwargs) -> str:
        res = 's' + str(self.SWI_IDX)

        self.SWI_IDX = self.SWI_IDX + 1

        return res

        






















