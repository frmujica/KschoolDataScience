#!/bin/bash
jupyter nbconvert TFMDraft.ipynb  --to slides --post serve --ServePostProcessor.ip="192.168.56.101" --ServePostProcessor.port=8910 --SlidesExporter.reveal_theme=sky --SlidesExporter.reveal_scroll=False --SlidesExporter.reveal_transition=concave
