1. **Save the File**
2. **Prepare the Input File**: Create a TXT file that contains the indicators and their types. The format of this file should be a CSV-like structure where each line contains an indicator and its type, separated by a comma. you can use the example file given **sample_indicators.txt**.
3. **Run the Script**: Use a terminal or command prompt to execute the script with the required arguments.
       - **Open Terminal/Command Prompt**: Navigate to the directory where your script is located.
       - **Run the Script with Required Arguments**: Use the following command to run the script. You need to provide the path to the input file and the rule name as arguments. You can also specify the output file name using the **--output** or **-o** option.

     python generate_yara.py indicators.txt MyYaraRule --output my_rule.yar

**indicators.txt** is the input file containing the indicators and their types.
**MyYaraRule** is the name of the YARA rule to be generated.
**--output my_rule.yar** is an optional argument to specify the output file name where the YARA rule will be saved. If not specified, the default is output.yar.


**Input File Format**
The input file should be a plain text file with each line containing an indicator and its type, separated by a comma. The script expects this format:
<img width="146" alt="image" src="https://github.com/fialhafizh/yara_gen/assets/172367792/9a851f0f-8c95-406e-9e6f-13455999bd0e">


Here’s an example content for indicators.txt:
d41d8cd98f00b204e9800998ecf8427e,md5
da39a3ee5e6b4b0d3255bfef95601890afd80709,sha1
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,sha256
http://example.com, url
malicious-domain.com,domain

**Example Output**
If you run the script with the example above:
python generate_yara.py indicators.txt MyYaraRule --output my_rule.yar

/*
   YARA Rule Set
   Author: xx
   Date: 2024-06-05
*/

rule MyYaraRule {
    meta:
        description = "Generated rule to detect IOCs from MyYaraRule"
    strings:
        $filehash_md5_0 = "d41d8cd98f00b204e9800998ecf8427e" ascii wide
        $filehash_sha1_0 = "da39a3ee5e6b4b0d3255bfef95601890afd80709" ascii wide
        $filehash_sha256_0 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ascii wide
        $url_0 = "http://example.com" wide
        $domain_0 = "malicious-domain.com" wide
    condition:
        any of ($filehash_md5_*) or any of ($filehash_sha1_*) or any of ($filehash_sha256_*) or any of ($url_*) or any of ($domain_*)
}

This YARA rule can be used to detect files or strings that match any of the indicators provided in the input file.

**Common Issues and Tips**
- Ensure the input file indicators.txt is formatted correctly.
- Check for extra spaces or missing commas which may cause the script to misinterpret the data.
- Make sure you have the necessary permissions to read the input file and write the output file.
- You can test the script with a small set of data first to ensure it behaves as expected.
