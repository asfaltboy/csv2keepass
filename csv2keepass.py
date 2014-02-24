"""
csv2keepass

Takes a csv file as input (either LastPass or KeePass 2.0 exported),
processes it and creates a KeePass 1.0 compatible XML file.

Original version forked from https://github.com/anirudhjoshi/lastpass2keepass
"""
import argparse
import csv
import datetime
import operator  # Toolkit
import re
import sys
import xml.etree.ElementTree as ET  # Saves data, easier to type

parser = argparse.ArgumentParser(description=__doc__)

# Strings
fileError = "You either need more permissions or the file does not exist."
lineBreak = "____________________________________________________________\n"


def formattedPrint(string):
    print lineBreak
    print string
    print lineBreak


def parse_input_file(inputFile):
    """
    Check files are readable and writable and parse embedded newlines
    """
    try:
        f = open(inputFile)
    except IOError:
        formattedPrint("Cannot read file: '%s' Error: '%s'" %
                       (inputFile, fileError))
        sys.exit()

    # Create XML file.
    outputFile = inputFile + ".export.xml"

    try:
        open(outputFile, "w").close()  # Clean.
        w = open(outputFile, "a")
    except IOError:
        formattedPrint("Cannot write to disk... exiting. Error: '%s'" %
                       (fileError))
        sys.exit()

    # Parser
    # Parse w/ delimter being comma, and entries separted by newlines

    h = re.compile('^http')  # Fix multi-line lastpass problems
    q = re.compile(',\d\n')

    for line in f.readlines():

        if h.match(line):
            w.write("\n" + line.strip())  # Each new line is based on this
        elif q.search(line):
            w.write(line.strip())  # Remove end line
        else:
            # Place holder for new lines in extra stuff
            w.write(line.replace('\n', '|\t|'))

    f.close()  # Close the read file.

    w.close()  # reuse same file - stringIO isn't working
    return outputFile


def get_results(parsedFile):
    results = {}
    with open(parsedFile, "rbU") as parsed_csv:
        reader = csv.DictReader(parsed_csv)

        if "Account" in reader.fieldnames:
            # use the keepass2 csv format mapping:
            # "Account","Login Name","Password","Web Site","Comments"
            mapping = {
                'title': 'Account',
                'username': 'Login Name',
                'password': 'Password',
                'url': 'Web Site',
                'comment': 'Comments',
            }
            for entry in reader:
                results.setdefault('Imported', []).append(entry)
        else:
            # use the lastpass csv format mapping:
            # url,username,password,extra,name,grouping,last_touch,launch_count,fav
            # or
            # url,username,password,extra,name,grouping,fav
            mapping = {
                'title': 'name',
                'username': 'username',
                'password': 'password',
                'url': 'url',
                'comment': 'extra',
            }
            if 'last_touch' in reader.fieldnames:
                mapping['lastaccess'] = 'last_touch'
            # Sort by categories
            for entry in reader:
                results.setdefault(entry['grouping'], []).append(entry)
    return sorted(results.iteritems(), key=operator.itemgetter(1)), mapping


def create_xml(results, mapping, outFile):
    # Keepass 1.0 XML generator
    xls_file = open(outFile, "w")
    xls_file.write("<!DOCTYPE KEEPASSX_DATABASE>")

    # Generate Creation date
    # Form current time expression.
    now = datetime.datetime.now()
    formattedNow = now.strftime("%Y-%m-%dT%H:%M")

    # Initialize tree
    # build a tree structure
    page = ET.Element('database')
    doc = ET.ElementTree(page)

    # loop through all entries
    for categoryEntries in results:

        category, entries = categoryEntries

        # Create head of group elements
        headElement = ET.SubElement(page, "group")
        ET.SubElement(headElement, "title").text = str(category).decode("utf-8")

        # neuther Lastpass nor keepass export icons
        ET.SubElement(headElement, "icon").text = "0"

        for entry in entries:
            entryElement = ET.SubElement(headElement, "entry")

            # Use decode for windows el appending errors
            for attribute in mapping:
                ET.SubElement(entryElement, attribute).text = str(
                    entry[mapping[attribute]]).replace(
                        '|\t|', '\n').strip('"').decode("utf-8")

            ET.SubElement(entryElement, 'icon').text = "0"
            ET.SubElement(entryElement, 'creation').text = formattedNow
            ET.SubElement(entryElement, 'lastmod').text = formattedNow
            ET.SubElement(entryElement, 'expire').text = "Never"

    doc.write(xls_file)
    xls_file.close()

if __name__ == '__main__':
    parser.add_argument('input_files', nargs='*')
    args = parser.parse_args()
    for inFile in args.input_files:
        outFile = parse_input_file(inFile)
        results, mapping = get_results(outFile)
        xml_file = create_xml(results, mapping, outFile)
        print lineBreak
        print "\n'%s' has been succesfully converted to the KeePassXML format." % (inFile)
        print "Converted data can be found in the '%s' file.\n" % (outFile)
        print lineBreak
