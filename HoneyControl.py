from ctypes import sizeof
from time import asctime
from typing import List, Tuple, Dict
import docker
from HoneyTree import *
from mininet.net import Containernet
from mininet.node import Controller
from mininet.net import OVSSwitch, Docker
from OptionGenerator import OptionGenerator
from collections import deque
from HoneyTracer import HoneyTracer
import os
import logging

MININET_PREFIX_NAME = "mn."

from functools import wraps
import time


def timeit(func):
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        print(f'Function {func.__name__}{args} {kwargs} Took {total_time:.8f} seconds')
        return result
    return timeit_wrapper

class HoneyControl(object):
    _instance = None
    _dockerClient = None
    _usedIps = {}
    _maxHostsPerLevel : List[int] = []
    _maxGrade = -1
    _numHosts = 0
    _generator : OptionGenerator = None
    _honeyRoot : HoneyTree
    _showLinkHistory : bool
    _prune_pause : bool
    _collapse_phase : bool
    compromisedChain : List[HoneyTree] = []
    globalTargets : Dict[int, HoneyTree] = {}
    globalIps : Dict[str, HoneyTree] = {}

    def __new__(cls):
        if cls._instance == None:
            logging.basicConfig(filename='honeyLogs.txt', filemode= 'a', format='%(name)s - %(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
            cls._dockerClient = docker.APIClient()
            cls._instance = super(HoneyControl, cls).__new__(cls)
        
        return cls._instance

    def sendPathToTrace(self, node : HoneyTree) -> Tuple[HoneyTree, str]:

        '''
        Finds path to mount bash history file and notify tracer to add as a tracing target
        Waits for tracer to return a watch descriptor
        Only called once for a specific node during the lifetime of the honeypot
        '''
        mountedHistoryFilePath : str = self._dockerClient.inspect_container(node.getName())["Mounts"][0]["Source"] + '/'
        mountedHistoryFilePath += ".bash_history"

        '''Makes sure to create the file'''
        histFile = open(mountedHistoryFilePath,"x")
        histFile.close()

        watchD = self.tracer.addTarget(mountedHistoryFilePath)

        logging.info(f'Created tracing target of path {node.path} with watchD {watchD}')

        self.globalTargets[watchD] = node
    
    def changeTopo(self, old : HoneyTree, new : HoneyTree):
        
        # prune old neighbors which are not proxy compromised containers or the new container
        if old != None:
            for sameGradeLinks in old.links:
                for link in sameGradeLinks:
                    if self.tryDisableAbstractLink(old, new, link, 0) == False:
                        res = self.tryDisableAbstractLink(old, new, link, 1)
                        if res == False:
                            logging.critical(f'Cannot prune link either way\n{link}')
                            exit(2)
        
        # generate upper grade links for the new container only if it wasn't previously compromised
        if not new.compromised:
            #generate list of list of links where a nested lists contain only links of same grade
            linkEndsOpts : Dict = self._generator.requestOptions('abstractLink', parentNode= new.parentNode)
            # pass down the chosen links received from generator
            self.inheritLinks(new, linkEndsOpts['upperLinks'])
        
        # generate or resume the new's neightbors
        for sameGradeLinks in new.links:
            for link in sameGradeLinks:
                if self.tryEnableAbstractLink(new, link, 0) == False:
                    res = self.tryEnableAbstractLink(new, link, 1)
                    if res == False:
                        logging.critical(f'Cannot activate link either way for link\n{link}')
                        exit(2)                    

        

        return

    def inheritLinks(self, new : HoneyTree, upperLinks : List[List[HoneyLink]]):
        
        '''
        Make the upper grade links pass down from new's node parent to itself

        Parent node deletes its former links
        '''
        for sameGradeLinks in upperLinks[:]:
            new.links.append(sameGradeLinks)
            
            for link in sameGradeLinks:
                if link.nodes[0] == new.parentNode:
                    link.nodes[0] = new
                else:
                    link.nodes[1] = new
                logging.debug(f'Passed down new link{str(link)}')
            new.parentNode.links.remove(sameGradeLinks)
        
        return

    def makeVirtualLink(self, node1 : HoneyTree, node2 : HoneyTree, abstractLink : HoneyLink):

        linkOpts = self._generator.requestOptions('virtualLink', containerName=node1.getName(), linkGrade=abstractLink.order)
        self.topo.addLink(node1.component, self.switch, **linkOpts)

        linkOpts = self._generator.requestOptions('virtualLink', containerName=node2.getName(), linkGrade=abstractLink.order)
        self.topo.addLink(node2.component, self.switch, **linkOpts)
        return
        
    
    def tryEnableAbstractLink(self, new : HoneyTree ,link : HoneyLink, idx : int) -> bool:
        
        if link.order == -1:
            if link.nodes[idx] == new:
                # the other end is of grade -1 but no container created
                if link.nodes[idx ^ 1].component == None:
                    newNeighbor = link.nodes[idx ^ 1]
                    self.createNode(newNeighbor)
                    # TODO add to virtual topology
                    self.makeVirtualLink(new, newNeighbor, link)
                
                # the other end is a previously created host node of grade -1
                else:
                    # unpause the neighbor if it was previously paused
                    containerName = link.nodes[idx ^ 1].getName()
                    isPaused = self._dockerClient.inspect_container(containerName)['State']['Paused']
                    if isPaused:
                        logging.info(f"Unpausing node at path{link.nodes[idx ^ 1].path}")
                        self._dockerClient.unpause(containerName)
                    #TODO add to virtual topology
                return True
            else:
                # the idx provided doesnt let us change the link, maybe try with its complement
                return False
                    
        # this is for upper grade links
        # check to see if the targeted link end is towards a previously generated node or not
        if link.nodes[idx] == new:
            if link.nodes[idx ^ 1].order == 0:
                # the other end is represented by a grade 0 node
                # find a free child node of grade -1 and create host
                otherEndParent = link.nodes[idx ^ 1]
                newNeighbor = self.findFreeChild(otherEndParent)
                if newNeighbor == None:
                    logging.critical(f'Cannot find free child from parent {otherEndParent.path} to link with grade {link.order} the node {new.path}')
                    exit(2)
                self.createNode(newNeighbor)
                link.nodes[idx ^ 1] = newNeighbor
                #TODO add to virtual topology
                self.makeVirtualLink(new, link.nodes[idx ^ 1], link)
                
            else:
                containerName = link.nodes[idx ^ 1].getName()
                isPaused = self._dockerClient.inspect_container(containerName)['State']['Paused']
                if isPaused:
                    #TODO add to virtual topology
                    logging.info(f"Unpausing node at path{link.nodes[idx ^ 1].path}")
                    self._dockerClient.unpause(containerName)
                #TODO : add node to virtual topology
            return True
        else:
            return False

    def createNode(self, newHost : HoneyTree):
        '''
        Request options for nodes with grade -1 for hosting new containers

        Also:

            1. notifyes tracer to monitor new container using sendPathToTrace() method

            2. requests options for upper grade links configuration ends used for abstract topology

            3. passes down the inherited upper grade links from their parent and deletes those links from their parent using inheritLinks() method
        '''
        hostOp = self._generator.requestOptions('node', nameHint=newHost.path)
        name = hostOp['name']
        del hostOp['name']
        newHost.component = self.topo.addDocker(name, cls= Docker, **hostOp)
        self.sendPathToTrace(newHost)
        linkEndOpts = self._generator.requestOptions('abstractLink', parentNode=newHost.parentNode)
        self.inheritLinks(newHost, linkEndOpts['upperLinks'])

        logging.info(f'Created new host\noptions:\n{hostOp}\nwith name:{name}\nat path:{newHost.path}\nwith links:{newHost.getLinksDescription()}')

    def findFreeChild(self, parent : HoneyTree) -> HoneyTree:

        for potentialChild in parent.childrenNodes:
            if potentialChild.component == None:
                return potentialChild
        
        logging.critical(f"No free child for parent of path {parent.path}")
        return None
        
    def tryDisableAbstractLink(self, old : HoneyTree, new : HoneyTree, link : HoneyLink, idx : int) -> bool:
        '''
        Try to disable the attacker's previous location neighbors by pausing the neighbors and removing their associated nodes from ContainerNet topology
        old : attacker's previous location node
        new : attacker's current location
        link : the targeted HoneyLink
        idx : either 0 or 1 depending on which end node from the link is old node
        Returns True if at the provided idx there is old node, otherwise False
        '''
        if link.nodes[idx] == old:
            # old is obviously compromised so all links have the other end to a previously generated node
            # try to disable other end if its not the attacker's current location (new) or part of the compromised chain
            oldNeighbor : HoneyTree = link.nodes[idx ^ 1]
            if oldNeighbor == new:
                logging.debug(f'Cannot prune node {oldNeighbor.path} because it is itself')
               
            elif oldNeighbor in self.compromisedChain:
                logging.debug(f'Cannot prune node {oldNeighbor.path} because it is part of compromised chain')
            else:
                #TODO remove from virtual network
                logging.debug(f'Successfully pruned old neighbor {oldNeighbor.path}')
                self._dockerClient.pause(oldNeighbor.getName())
            return True
            
        logging.debug(f'Failed disabling link at idx {idx} for old {old.path}')
        return False


    def main(self, generator : OptionGenerator):


        self._generator = generator

        print(f'PID is {os.getpid()}')

        self.initTopo()

        while True :

            watchD = self.tracer.waitEvent()

            #TODO use logger
            logging.critical(f'Caught suspicious activity in container with watchFd {watchD}')
            if watchD == None:
                break

            currentNode : HoneyTree = self.globalTargets[watchD]

            if self.compromisedChain == []:
                self.changeTopo(None, currentNode)
                self.compromisedChain.append(currentNode)
                currentNode.compromised = True
            
            if currentNode != self.compromisedChain[-1]:
                self.changeTopo(self.compromisedChain[-1], currentNode)
                self.compromisedChain.append(currentNode)
                currentNode.compromised = True
            
            compromisedPaths = list(map(lambda t: t.path, self.compromisedChain))

            logging.info(f'Current compromised chain\n{compromisedPaths}')
        
        return
    
    def defaultTree(self, root : HoneyTree):

        '''
        Create topology without linking nodes of the same order
        BFS aproach
        '''
        q = deque()

        q.append(root)

        while len(q) > 0:

            
            current : HoneyTree = q.popleft()
            

            for th in range(0, self._maxHostsPerLevel[current.order]):
                newPath = current.path[:]
                newPath.append(th)
                child : HoneyTree = HoneyTree(current, None, current.order -1, newPath)
                
                current.childrenNodes.append(child)

                # only continue going in depth only if the child is not a basic logical node of grade 0
                if child.order > -1:
                    q.append(child)
        return
        
    def defaultLinks(self, root : HoneyTree):
        '''
        Link nodes of the same order with HoneyLinks
        BFS aproach
        '''
        
        q = deque()

        q.append(root)

        while len(q) > 0:

            current : HoneyTree = q.popleft()
            
            for i in range(len(current.childrenNodes) - 1):
                for j in range(i + 1, len(current.childrenNodes)):
                    ln = HoneyLink(current.order - 1, [current.childrenNodes[i], current.childrenNodes[j]])
                    current.childrenNodes[i].links[-1].append(ln)
                    current.childrenNodes[j].links[-1].append(ln)
            
            for child in current.childrenNodes:
                if child.order > -1:
                    q.append(child)
        return
    
    def propagatePhase(self, root : HoneyTree):
        '''
        Propagate by forcing every node of grade greater than 0
        to distribute equally its links to its children 
        BFS aproach
        '''

        def splitList(l : List, n : int) -> List[List]:

            res = []

            quota = int(len(l) / n)

            for i in range(n):
                res.append( l[i * quota : (i + 1) * quota] )

            return res


        q = deque()

        q.append(root)

        while len(q) > 0:

            current : HoneyTree = q.popleft()

            if current.order == 0:
                break

            # if the current is not root then we transform the higher order links passed from its parent
            if current != root:
                
                # we iterate over every list of links with the same grade and we split them equally to the children
                for ln in current.links:
                    
                    # split the links equally, now he have a list of list, where each nested list contains links for 1 child
                    split_links = splitList(ln, len(current.childrenNodes))

                    # before giving the links to the children change the ending points
                    # contained into the links with the respective children (collapse the links 1 order down)
                    for i in range(len(current.childrenNodes)):
                        for sln in split_links[i]:
                            if sln.nodes[0].order != current.order - 1:
                                if self._showLinkHistory:
                                    sln.history.append([sln.nodes[0]])
                                sln.nodes[0] = current.childrenNodes[i]

                            elif sln.nodes[1].order != current.order - 1:
                                if self._showLinkHistory:
                                    sln.history[-1].append(sln.nodes[1])
                                sln.nodes[1] = current.childrenNodes[i]

                        # give the splitted links to the children
                        # Give to Caesar What Is Caesar’s
                        current.childrenNodes[i].links.append(list(split_links[i]))

                
                for child in current.childrenNodes:
                    q.append(child)

            else:
                # traverse the children when current is 
                for child in current.childrenNodes:
                    q.append(child)

        return

    def collapsePhase(self, root : HoneyTree):
        '''
    Physically colapse the logical tree, only preserving the grade 0 nodes and a new root, while the old tree is deleted
        DFS aproach
        '''
        q = deque()

        q.append(root)

        while len(q) > 0:

            current : HoneyTree = q.popleft()

            for ch in current.childrenNodes:
                if ch.order == 0:
                    ch.parentNode = self._honeyRoot
                    self._honeyRoot.childrenNodes.append(ch)
                q.append(ch)
        return
    @timeit
    def initTopo(self):

        
        root : HoneyTree = HoneyTree(None, None, self._maxGrade, [])

        # both of them represent the Initialization phase
        self.defaultTree(root)

        self.defaultLinks(root)

        # propagation phase                    
        self.propagatePhase(root)

        self._honeyRoot = HoneyTree(None, None, self._maxGrade, [])

        if self._collapse_phase:
            self.collapsePhase(root)
        else:
            self._honeyRoot = root

        #logging.warning('\n' + printNodes(self._honeyRoot))

        root = None

        self.topo = Containernet(controller = Controller)

        self.topo.addController('c0')

        switchOpts = self._generator.requestOptions('switch')

        sw_name = switchOpts['name']

        del switchOpts['name']

        self.switch = self.topo.addSwitch(sw_name, OVSSwitch, **switchOpts)

        self.tracer = HoneyTracer()

        # start the controller and the switch
        self.topo.start()

        # comment this for evaluation of memory and time
        self.createNode(self._honeyRoot.childrenNodes[0].childrenNodes[0])

        return


    def exitTopo(self):

        self.topo.stop()


def sameCellZero(path1, path2) -> bool:

    for i in range(len(path1)):
        if path1[i] != path2[i]:
            return False
    
    return True
