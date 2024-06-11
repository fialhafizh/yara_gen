import argparse
from datetime import date

def parse_txt_file(txt_file):
    indicators = []
    with open(txt_file, 'r') as file:
        for line in file:
            parts = line.strip().split(',')
            if len(parts) == 2:
                indicator, ioc_type = parts
                indicators.append((indicator.strip(), ioc_type.strip().lower()))
    return indicators

def generate_yara_rule(rule_name, indicators):
    rule = f'/*\n'
    rule += f'   YARA Rule Set\n'
    rule += f'   Author: Daffi\n'
    rule += f'   Date: {date.today()}\n'
    rule += f'*/\n\n'

    rule += f'rule {rule_name} {{\n'
    rule += '    meta:\n'
    rule += f'        description = "Generated rule to detect IOCs from {rule_name}"\n'
    rule += '    strings:\n'
    
    md5_count = sha1_count = sha256_count = url_count = domain_count = 0
    
    for indicator, ioc_type in indicators:
        if ioc_type == 'md5':
            rule += f'        $filehash_md5_{md5_count} = "{indicator}" ascii wide\n'
            md5_count += 1
        elif ioc_type == 'sha1':
            rule += f'        $filehash_sha1_{sha1_count} = "{indicator}" ascii wide\n'
            sha1_count += 1
        elif ioc_type == 'sha256':
            rule += f'        $filehash_sha256_{sha256_count} = "{indicator}" ascii wide\n'
            sha256_count += 1
        elif ioc_type == 'url':
            rule += f'        $url_{url_count} = "{indicator}" wide\n'
            url_count += 1
        elif ioc_type == 'domain':
            rule += f'        $domain_{domain_count} = "{indicator}" wide\n'
            domain_count += 1
        else:
            rule += f'        $str{i} = "{indicator}"\n'
    
    rule += '    condition:\n'
    conditions = []
    if md5_count > 0:
        conditions.append('any of ($filehash_md5_*)')
    if sha1_count > 0:
        conditions.append('any of ($filehash_sha1_*)')
    if sha256_count > 0:
        conditions.append('any of ($filehash_sha256_*)')
    if url_count > 0:
        conditions.append('any of ($url_*)')
    if domain_count > 0:
        conditions.append('any of ($domain_*)')
    
    rule += ' or '.join(conditions)
    rule += '\n}'
    return rule

def main():
    parser = argparse.ArgumentParser(description='Generate YARA rules from a TXT file with indicators and their types.')
    parser.add_argument('input_file', help='Input TXT file')
    parser.add_argument('rule_name', help='Name of the YARA rule')
    parser.add_argument('--output', '-o', help='Output file to save the YARA rule', default='output.yar')
    
    args = parser.parse_args()
    
    indicators = parse_txt_file(args.input_file)
    
    yara_rule = generate_yara_rule(args.rule_name, indicators)
    
    with open(args.output, 'w') as file:
        file.write(yara_rule)
    
    print(f'YARA rule saved to {args.output}')

if __name__ == '__main__':
    main()
