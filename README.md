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
<img width="299" alt="image" src="https://github.com/fialhafizh/yara_gen/assets/172367792/eba1dcc8-dfb9-42b0-bf6f-34e5858eefae">





Here’s an example content for indicators.txt:

<img width="620" alt="image" src="https://github.com/fialhafizh/yara_gen/assets/172367792/475e656f-8117-4332-8340-188525b34bad">


**Example Output**
If you run the script with the example above:
python generate_yara.py indicators.txt MyYaraRule --output my_rule.yar

<img width="959" alt="image" src="https://github.com/fialhafizh/yara_gen/assets/172367792/8ed38cbd-5006-43fd-a520-e6f98b15c6e7">


This YARA rule can be used to detect files or strings that match any of the indicators provided in the input file.

**Common Issues and Tips**
- Ensure the input file indicators.txt is formatted correctly.
- Check for extra spaces or missing commas which may cause the script to misinterpret the data.
- Make sure you have the necessary permissions to read the input file and write the output file.
- You can test the script with a small set of data first to ensure it behaves as expected.
