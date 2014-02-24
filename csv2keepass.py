"""
csv2keepass

Takes a csv file as input (either LastPass or KeePass 2.0 exported),
processes it and creates a KeePass 1.0 compatible XML file.

Original version forked from https://github.com/anirudhjoshi/lastpass2keepass
"""
import argparse
import csv
import datetime
import logging
import operator  # Toolkit
import re
import sys
import xml.etree.ElementTree as ET  # Saves data, easier to type

parser = argparse.ArgumentParser(description=__doc__)

console_handler = logging.StreamHandler()
logger = logging.getLogger()
logger.addHandler(console_handler)
logger.setLevel(logging.WARN)

# Strings
fileError = "You either need more permissions or the file does not exist."
lineBreak = "____________________________________________________________"
tempFile = 'temp_parsed.csv'


def formattedPrint(string):
    logger.info(lineBreak)
    logger.info(string)
    logger.info(lineBreak)


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

    try:
        w = open(tempFile, "w")
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
    return tempFile


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


def create_tree(results, mapping, db_elm):
    # Generate Creation date
    # Format current time expression.
    now = datetime.datetime.now()
    formattedNow = now.strftime("%Y-%m-%dT%H:%M")

    # loop through all entries
    for categoryEntries in results:

        category, entries = categoryEntries
        if not category:
            # default category: "Uncategorized"
            category = 'Uncategorized'

        # Create head of group elements
        logging.debug("Adding group to db elm %s for category %s", db_elm, category)
        headElement = ET.SubElement(db_elm, "group")
        ET.SubElement(headElement, "title").text = str(category).decode("utf-8")

        # neuther Lastpass nor keepass export icons
        ET.SubElement(headElement, "icon").text = "0"

        for entry in entries:
            entryElement = ET.SubElement(headElement, "entry")

            # Use decode for windows el appending errors
            for attribute in mapping:
                ustr = str(entry[mapping[attribute]]).decode("utf-8")
                ET.SubElement(entryElement, attribute).text = ustr.replace(
                    '|\t|', '\n').replace('"', '')

            ET.SubElement(entryElement, 'icon').text = "0"
            ET.SubElement(entryElement, 'creation').text = formattedNow
            ET.SubElement(entryElement, 'lastmod').text = formattedNow
            ET.SubElement(entryElement, 'expire').text = "Never"


def write_xml(doc, filePath):
    logging.debug("Writing doc %s to file %s", doc, filePath)
    ofile = open(filePath, 'w')
    ofile.write("<!DOCTYPE KEEPASSX_DATABASE>")
    doc.write(ofile)
    ofile.close()


if __name__ == '__main__':
    parser.add_argument('input_files', nargs='*')
    parser.add_argument('-m', '--merged', help='Use one xml file for output ('
                        'default: create an input file for each of the input files)',
                        default=None)
    parser.add_argument('-v', '--verbose', help='Print out more verbose output', action="count")
    args = parser.parse_args()
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARN)

    mergedFile = args.merged

    db_elm = ET.Element('database')

    for inFile in args.input_files:
        tempFile = parse_input_file(inFile)
        results, mapping = get_results(tempFile)
        create_tree(results, mapping, db_elm=db_elm)

        if not mergedFile:
            doc = ET.ElementTree(db_elm)
            outFile = inFile + '.export.xml'
            write_xml(doc, outFile)
            logger.info(lineBreak)
            logger.info("'%s' has been succesfully converted to the KeePassXML format.", inFile)
            logger.info("Converted data can be found in the '%s' file.", outFile)
            logger.info(lineBreak)
            db_elm = ET.Element('database')

    if mergedFile:
        doc = ET.ElementTree(db_elm)
        write_xml(doc, mergedFile)
