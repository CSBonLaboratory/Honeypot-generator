from functools import reduce
from typing import Dict, List
from HoneyControl import HoneyControl
import json, sys
from HostOptionGenerator import HostOptionGenerator

def debugOptionGuard(configData : Dict, missingErr : str, typeErr : str):

    if configData.get("debug") is None:
        print('Option debug ' + missingErr)
        exit(1)
    
    if configData['debug'].get('linkHistory') is None:
        print('Option debug.linkHistory' + missingErr)
        exit(1)
    elif type(configData['debug']['linkHistory']) is not bool:
        print('Option debug.linkHisotry' + typeErr + 'bool')
        exit(1)
    
    hctl = HoneyControl()

    hctl._showLinkHistory = configData['debug']['linkHistory']


def constraintsOptionGuard(configData : Dict, missingErr : str, typeErr : str):
    if configData.get('constraints') is None:
        print('Option constraints' + missingErr)
        exit(1)
    
    if configData['constraints'].get('grade') is None:
        print('Option constraints.grade' + missingErr)
        exit(1)
    elif type(configData['constraints']['grade']) is not int:
        print('Option constraints.grade' + typeErr + 'int')
        exit(1)
    elif configData['constraints']['grade'] not in [-1, 0]:
        print("Option constraints.grade is not a constraint for recursively-defined topologies")
        print("Possible values: -1, 0")
        exit(1)

    if configData['constraints'].get('numHosts') is None:
        print('Option constraints.numHosts' + missingErr)
        exit(1)
    elif type(configData['constraints']['numHosts']) is not int:
        print('Option constraints.numHosts' + typeErr)
        exit(1)
    
    if configData['constraints'].get('links') is None:
        print("Option constraints.links" + missingErr)
        exit(1)

    return


def optimizationOptionGuard(configData : Dict, missingErr : str, typeErr : str):
    if configData.get('optimizations') is None:
        print('Option optimizations' + missingErr)
        exit(1)
    
    if configData['optimizations'].get('enableCollapse') is None:
        print('Option optimizations.enableCollapse' + missingErr)
    elif type(configData['optimizations']['enableCollapse']) is not bool:
        print('Option optimizations.enableCollapse' + typeErr)

    if configData['optimizations'].get('enablePrunePause') is None:
        print('Option optimizations.enablePrunePause' + missingErr)
    elif type(configData['optimizations']['enablePrunePause']) is not bool:
        print('Option optimizations.enablePrunePause' + typeErr)
    
    hctl = HoneyControl()

    hctl._prune_pause = configData['optimizations']['enablePrunePause']

    hctl._collapse_phase = configData['optimizations']['enableCollapse']

    return

def configure(configData : Dict):

    missingErr : str = " is missing"
    typeErr : str = " is not of type "


    constraintsOptionGuard(configData, missingErr, typeErr)

    debugOptionGuard(configData, missingErr, typeErr)

    optimizationOptionGuard(configData, missingErr, typeErr)

    
    maxConstraintLinkGrade = max(list(map( lambda ks : int(ks),configData['constraints']['links'].keys())))

    maxGrade = maxConstraintLinkGrade + 1

    constraints = []
    for grade in range(maxGrade):
        gradeStr = str(grade)
        if gradeStr not in configData['constraints']['links']:
            print(f'Missing constraint grade {grade} out of {maxGrade}')
            exit(1)
        constraints.append(configData['constraints']['links'][gradeStr])
    
    hctl = HoneyControl()

    hctl._maxHostsPerLevel = [1 for _ in range(maxGrade + 1)]

    hctl._maxGrade = maxGrade

    hctl._numHosts = configData['constraints']['numHosts']
    
    hctl._maxHostsPerLevel[0] = hctl._numHosts

    hctl._maxHostsPerLevel = coreAlgo(hctl._maxHostsPerLevel, maxGrade, constraints, configData['constraints']['grade'])

    f = open('nana.txt', "wt")
    f.write(str(hctl._maxHostsPerLevel))

    f.close()


def coreAlgo(maxHostsPerLevel : List[int], maxGrade : int, constraints : List[int], constraintGrade : int):

    previousProduct : List[int] = [1 for _ in range(len(maxHostsPerLevel))]
    if constraintGrade == -1:
        for i in range(len(constraints)):
            constraints[i] = constraints[i] * maxHostsPerLevel[0]
    
    # Dynamic programming aproach is more efficient, store the product instead of using: reduce(lambda a,b : a * b, maxHostsPerLevel[1 : grade], 1)
    maxHostsPerLevel[1] = constraints[0] + 1
    previousProduct[1] = maxHostsPerLevel[1]
    for grade in range(2, maxGrade + 1):
        maxHostsPerLevel[grade] = constraints[grade - 1] * previousProduct[grade - 1] + 1
        previousProduct[grade] = maxHostsPerLevel[grade] * previousProduct[grade - 1]

    # one massive structure of grade maxGrade + 1 which incorporates the whole topology
    maxHostsPerLevel.append(1)

    print(maxHostsPerLevel)

    print('HOSTS ' + str(reduce(lambda a,b : a *b, maxHostsPerLevel, 1)))
    return maxHostsPerLevel




def main():

    if len(sys.argv) < 2:
        print("Usage: python3 main.py <config json file>")
        exit(1)

    configFile = open(sys.argv[1])

    configData = json.load(configFile)

    configure(configData)

    hctl = HoneyControl()

    generator = HostOptionGenerator(globalIp = '10.0.0.1', mask=16)

    hctl.main(generator)

if __name__ == "__main__":
    main()