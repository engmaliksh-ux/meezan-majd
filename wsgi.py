import sys
import os

# مسار المشروع
project_home = '/home/MalikMohs/makhzan_alkhair'

if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.chdir(project_home)

# المفتاح السري
os.environ['SECRET_KEY'] = '3b6e68f4f9271ec793ec738a612c7349c7db77690f01d3ab9a445015e83cd4a8'

from app import app as application