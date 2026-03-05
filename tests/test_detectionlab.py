import adexpsnapshot
import os

def test_full_parse():
    path = os.path.join(os.path.dirname(__file__), 'data/detectionlab.dat')
    with open(path, "rb") as fh:
        ades = adexpsnapshot.ADExplorerSnapshot(fh, '/tmp')
        ades.outputBloodHound()
        ades.outputObjects()
