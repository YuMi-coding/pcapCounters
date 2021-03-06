#!/usr/bin/env python3
import argparse
from src.parser import labelParser, labelTypes

parser = argparse.ArgumentParser(description="Parse the labeling of datasets into spec json files")
parser.add_argument("-i", "--input", help="Input the labeling file", default="../DDoS-eval/BOT_IOT/DDoS_HTTP.csv")
parser.add_argument("-o", "--output", help="Output of spec jsons", default="../DDoS-eval/BOT_IOT/DDoS_HTTP.json")

if __name__ == "__main__":
    args = parser.parse_args()
    lp = labelParser.LabelParser(labelTypes.BOT_IOT_DDOS_HTTP)
    lp.parseLabels(args.input, args.output)