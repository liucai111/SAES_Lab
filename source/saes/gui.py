"""Compatibility entry point; the new stage-specific UI lives in saes.ui."""
from .ui.app import SAESApp, main
from .ui.config import MODES
if __name__=="__main__":main()
