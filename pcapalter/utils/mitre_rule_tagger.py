from idstools import rule as idsRule
import logging
import sys
import argparse
import os
from suricataparser import parse_file

# import rule_transformer
from .rule_transformer import RuleTransformer


def progressbar(it, prefix="", size=60, out=sys.stdout):
    # Code taken from https://stackoverflow.com/questions/3160699/python-progress-bar
    count = len(it)

    def show(j):
        x = int(size * j / count)
        print(
            f"{prefix}[{u'█'*x}{('.'*(size-x))}] {j}/{count}",
            end="\r",
            file=out,
            flush=True,
        )

    show(0)
    for i, item in enumerate(it):
        yield item
        show(i + 1)
    print("\n", flush=True, file=out)

def main(file_path):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - <%(levelname)s> - %(message)s"
    )
    logger = logging.getLogger()

    logger.info("MITRE tagging - Starting up")

    inputfile = file_path
    outputfile = "mitre_all.rules"

    transformer = RuleTransformer('mitre_technique_id')

    logger.info("MITRE tagging - Reading inputfile")
    rules = idsRule.parse_file(inputfile)

    f = open(outputfile, "w", encoding='utf-8', errors='replace' )
    logger.info("MITRE tagging - Adding tags to rules")
    for rule in progressbar(rules):
        r = transformer.passRegex(rule)
        f.write(str(r) + "\n")
    
    f.close()

    logger.info("MITRE tagging - Finished tagging, rules written to %s", outputfile)

    return outputfile

