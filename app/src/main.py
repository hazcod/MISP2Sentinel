#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""In-house script for pushing ICC MISP IOCs onto Sentinel and Defender. MS' tool is overly complex and buggy."""

import sys
from datetime import datetime, timezone
from loguru import logger
from misp import get_misp_attributes
from msgraph import MSGraphConnector
from converter import transform_misp_to_msgraph
import config

def __setup_logger():
    logger.remove()
    log_file_name = f'misp_to_msgraph-{datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y%m%d_%H%MZ")}.log'
    logger.add(log_file_name, level="DEBUG")
    logger.add(sys.stderr, level="INFO", format='{message}')

def main():
    '''Main script/function of the whole project.'''
    __setup_logger()
    logger.info("Starting")
    msgraph_connector = MSGraphConnector()
    misp_attributes = get_misp_attributes()
    combined_misp_msgraph_dicts = list(map(lambda misp_attr: transform_misp_to_msgraph(misp_attr, config), misp_attributes))
    transform_counters = {
        'SUCCESS': 0,
        'IGNORED': 0,
        'IGNORE DEFENDER': 0,
        'UNKNOWN': 0,
        'CORRUPT': 0
    }
    push_counter = 0
    for combined_misp_msgraph_dict in combined_misp_msgraph_dicts:
        transform_counters[combined_misp_msgraph_dict['transform_status']] += 1
        if combined_misp_msgraph_dict['transform_status'] == "SUCCESS":
            msgraph_connector.post_one_ioc_to_graph(combined_misp_msgraph_dict)
            push_counter += 1 if combined_misp_msgraph_dict['post_status'] == "SUCCESS" else 0
    num_total = len(combined_misp_msgraph_dicts)
    logger.info(f'Total number of MISP attributes pulled: {num_total}.')
    if num_total > 0:
        __print_stats("Num of MISP attrs correctly transformed to MS Graph: ", transform_counters['SUCCESS'], num_total)
        __print_stats("Num of MISP attrs ignored: ", transform_counters['IGNORED'], num_total)
        __print_stats("Num of MISP attrs ignored (Defender): ", transform_counters['IGNORE DEFENDER'], num_total)
        __print_stats("Num of MISP attrs unknown/corrupt: ", transform_counters['UNKNOWN'], num_total)
        __print_stats("Num of MISP attrs pushed to MS Graph: ", push_counter, num_total)
    logger.info("Finished")

def __print_stats(text, count, total):
    logger.info(f'''{text}: {count}. {100*count/total:.2f}%.''')

if __name__ == "__main__":
    main()
