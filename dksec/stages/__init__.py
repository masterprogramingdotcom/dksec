"""
Registry of all 9 Product Security lifecycle stages.
"""

from typing import Dict, Type
from dksec.stages.base import BaseStage
from dksec.stages.stage1_threat_model import Stage1ThreatModel
from dksec.stages.stage2_requirements import Stage2Requirements
from dksec.stages.stage3_sast_sca_secrets import Stage3SastScaSecrets
from dksec.stages.stage4_dast_api import Stage4DastApi
from dksec.stages.stage5_manual_wstg import Stage5ManualWstg
from dksec.stages.stage6_vapt import Stage6Vapt
from dksec.stages.stage7_fix_retest import Stage7FixRetest
from dksec.stages.stage8_signoff import Stage8Signoff
from dksec.stages.stage9_monitoring import Stage9Monitoring

STAGE_CLASSES: Dict[int, Type[BaseStage]] = {
    1: Stage1ThreatModel,
    2: Stage2Requirements,
    3: Stage3SastScaSecrets,
    4: Stage4DastApi,
    5: Stage5ManualWstg,
    6: Stage6Vapt,
    7: Stage7FixRetest,
    8: Stage8Signoff,
    9: Stage9Monitoring,
}

def get_stage_instance(stage_id: int) -> BaseStage:
    if stage_id not in STAGE_CLASSES:
        raise ValueError(f"Unknown stage ID: {stage_id}. Must be between 1 and 9.")
    return STAGE_CLASSES[stage_id]()
