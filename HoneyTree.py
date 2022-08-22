from __future__ import annotations
from ctypes import Union
from functools import reduce
from typing import List
from mininet.net import OVSSwitch
from mininet.net import Docker
from collections import deque

class HoneyLink(object):
    nodes : List[HoneyTree]
    order : int
    history : List[List[HoneyTree]]
    def __init__(self, order, args):
        self.nodes = args
        self.order = order
        self.history = []
        return None
    def __str__(self) -> str:
        parent : HoneyTree = self.nodes[0].parentNode
        ans = f"grade : {self.order} " 
        ans += f"nodes : {self.nodes[0].path} -- {self.nodes[1].path} "
            
        ans += 'from past : '

        for pastPair in self.history:
            ans += f"{pastPair[0].path} -- {pastPair[1].path}, "
    
        return ans



class HoneyTree(object):
    MININET_PREFIX = 'mn.'
    def __init__(self, parent, component, order, path):
        self.parentNode : HoneyTree = parent
        self.component : Union[Docker, OVSSwitch, None] = component
        self.childrenNodes : List[HoneyTree] = []
        self.links : List[List[HoneyLink]] = [[]]
        self.order : int = order
        self.path : List[int] = path
        self.compromised = False
        self.watchD : int = None
    
    def __str__(self) -> str:
        return str(self.path)

    def getLinksDescription(self) -> str:
        
        res = ''
        for sameGradeLinks in self.links:
            for link in sameGradeLinks:
                res+= f'{str(link)}\n'
        return res

    def getName(self) -> str:
        
        if isinstance(self.component, Docker):
            return self.MININET_PREFIX + self.component.name
        elif isinstance(self.component, OVSSwitch):
            return self.component.name
        
        return None

def printLinks(node : HoneyTree):

    q = deque()

    q.append(node)

    while len(q) > 0:

        current : HoneyTree = q.popleft()
        print(current.path)

        if current == node:

            for child in current.childrenNodes:
                q.append(child)
        else:
                
            for orderedLinkList in current.links:
                print(*orderedLinkList, sep='\n', end='\n')

            for child in current.childrenNodes:
                q.append(child)
            
    return

def printNodes(node : HoneyTree, tabs : int = 0, res = []) -> str:


    res.append(tabs * '\t')

    res.append(f'{node}\n')

    tabs += 1
    
    for child in node.childrenNodes:
        printNodes(child, tabs=tabs, res=res)
    
    def helper(a : str, b :str) -> str:
        a += b
        return a
    return reduce(helper, res)

    


if __name__ == "__main__":
    print("asaa")