"""
Initial file to run the GSD Analysis
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as plticker
import json
import time
from dateutil import parser
import ast
from genson import SchemaBuilder

"""Replace with local gsd-database clone"""
local_gsd = f"../gsd-database/"


def get_gsd_list(file=None, saveFile=False):
    """
    Returns a dataframe of all the GSD entries.
    :param file: Known file from previous run so you don't have to parse the GSD database again
    :param saveFile: Save file on an initial run
    :return: A dataframe of all the GSD entries and gsd_update_time
    """

    """Get the NVD Update Time from the txt file in GSD"""
    temp_gsd_update_time = open(f'{local_gsd}nvd_updated_time.txt', 'r').readlines()[0].split(":")[:-1]
    temp_gsd_update_time = parser.parse("".join(temp_gsd_update_time))

    """Create a filename to save list of all GSD entries"""
    gsd_entry_filename = f"./data/gsd_entries_{str(temp_gsd_update_time).split(' ')[0].replace('-','')}.csv"

    """Check if file exists so we don't have to reload data"""
    if os.path.exists(gsd_entry_filename):
        temp_gsd_list = pd.read_csv(gsd_entry_filename)
    else:
        """Get list of available years within GSD"""
        gsd_years = [name for name in os.listdir(local_gsd) if os.path.isdir(os.path.join(local_gsd, name))]
        gsd_years = [name for name in gsd_years if "." not in name]
        gsd_years.sort()

        """Base DF to hold data"""
        temp_gsd_list = pd.DataFrame(columns=["path"])

        """Walk through the gsd-database and obtain the GSD json files"""
        for r, d, f in os.walk(local_gsd):
            if r.split("/")[-2] in gsd_years:
                temp_gsd_file = [f"{r}/{gsd}" for gsd in f]
                temp_gsd = pd.DataFrame(temp_gsd_file, columns=["path"])
                temp_gsd_list = pd.concat([temp_gsd_list, temp_gsd])

        """Set the year/group_id/gsd value for the DF"""
        temp_gsd_list["year"] = temp_gsd_list.apply(lambda row: row["path"].split("/")[-3], axis=1)
        temp_gsd_list["group_id"] = temp_gsd_list.apply(lambda row: row["path"].split("/")[-2], axis=1)
        temp_gsd_list["gsd"] = temp_gsd_list.apply(lambda row: row["path"].split("/")[-1], axis=1)

        temp_gsd_list["api"] = temp_gsd_list.apply(
            lambda x: f"https://raw.globalsecuritydatabase.org/{x['path'].split('/')[-1].strip('.json')}",
            axis=1)

        """Reset the index"""
        temp_gsd_list = temp_gsd_list.reset_index(drop=True)

        """Save file if desired"""
        temp_gsd_list.to_csv(gsd_entry_filename, encoding='utf-8', index=False)

    return temp_gsd_list, temp_gsd_update_time


def visualize_gsd(gsd_items, analysis_date):
    """
    Create a figure of the GSD item counts by year
    :param gsd_items: Dataframe of GSD entries
    :param analysis_date: Date of GSD NVD update time
    :return: None
    """

    """Count by year"""
    gsd_year_counts = gsd_items["year"].value_counts().rename_axis('year').reset_index(name='counts').sort_values('year')

    """Create a figure of the size of GSD by year"""
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(gsd_year_counts["year"], gsd_year_counts["counts"])

    """Set some labels"""
    ax.set_xlim(gsd_year_counts["year"].min(), gsd_year_counts["year"].max())
    ax.set_ylim(0)
    plt.xticks(rotation=75)
    loc = plticker.MultipleLocator(base=1.0)  # this locator puts ticks at regular intervals
    ax.xaxis.set_major_locator(loc)
    plt.yticks(np.arange(0, gsd_year_counts["counts"].max()+5000, 5000))
    ax.get_yaxis().set_major_formatter(plticker.FuncFormatter(lambda x, p: format(int(x), ',')))
    ax.set_ylabel('Count')
    ax.set_title(f'Count of GSD Entries by Year')
    plt.grid(color='gray', linestyle='-', linewidth=0.2)

    """Add a box with some key values"""
    textstr = f"Total Entries = {len(gsd_items):,} \nDate = {analysis_date}"
    props = dict(boxstyle='square', facecolor='white', alpha=1)
    # place a text box in upper left corner
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=10,
            verticalalignment='top', bbox=props)

    """Save Fig"""
    plt.savefig("./data/figs/gsd_total_count.png", bbox_inches="tight")


def generate_complete_gsd_schema(gsd_items_complete):
    """
    Generates a complete GSD schema for all possible data entries
    :param gsd_items_complete: Dataframe of GSD entries
    :return: GSD schema and checklist of various counts
    """

    # Check if schema and master_checklist already exists so we don't have to re-run
    if os.path.exists(f"./data/schemas/gsd_complete_schema.json") and os.path.exists(f"./data/gsd_counts.csv"):
        with open(f"./data/schemas/gsd_complete_schema.json", 'r') as f:
            schema = json.load(f)
            f.close()
        master_checklist = pd.read_csv(f"./data/gsd_counts.csv")
    else:
        """"Hold the complete schema"""
        builder = SchemaBuilder()

        """Holds various counts of the various object types in the GSD"""
        master_checklist = pd.DataFrame()

        """Loop through each GSD entry, loads the JSON, adding object to Genson Schema, and creating a master dataframe"""
        for index, gsd in gsd_items_complete.iterrows():
            print(f"{index}/{len(gsd_items_complete)}")
            with open(gsd["path"], 'r') as f:
                data = json.load(f)

                builder.add_object(data)

                temp_check_values = pd.DataFrame([gsd["path"]], columns=["gsd_path"])

                """Identify any JSONs without a GSD object"""
                if '\'GSD\':' not in str(data):
                    temp_check_values["missingGSD"] = 1
                else:
                    temp_check_values["missingGSD"] = 0

                """Identify any JSONs with a GSD object"""
                if '\'GSD\':' in str(data):
                    temp_check_values["GSD"] = 1
                    try:
                        temp_check_values["GSD_alias"] = data["GSD"]["alias"]
                    except:
                        temp_check_values["GSD_alias"] = "Missing"
                else:
                    temp_check_values["GSD"] = 0
                    temp_check_values["GSD_alias"] = None

                """Identify any JSONs with a OSV object"""
                if '\'OSV\':' in str(data):
                    temp_check_values["OSV"] = 1
                else:
                    temp_check_values["OSV"] = 0

                """Identify any JSONs with a overlay object"""
                if '\'overlay\':' in str(data):
                    temp_check_values["overlay"] = 1
                else:
                    temp_check_values["overlay"] = 0

                """Identify any JSONs with a cve.org object"""
                if '\'cve.org\':' in str(data):
                    temp_check_values["cve.org"] = 1
                    try:
                        temp_check_values["cve_org_id"] = data["namespaces"]["cve.org"]["CVE_data_meta"]["ID"]
                    except:
                        temp_check_values["cve_org_id"] = None
                else:
                    temp_check_values["cve.org"] = 0
                    temp_check_values["cve_org_id"] = None

                """Identify any JSONs with a nvd.nist.gov object"""
                if '\'nvd.nist.gov\':' in str(data):
                    temp_check_values["nvd.nist.gov"] = 1
                    try:
                        temp_check_values["nvd_id"] = data["namespaces"]["nvd.nist.gov"]["cve"]["CVE_data_meta"]["ID"]
                    except:
                        temp_check_values["nvd_id"] = None
                else:
                    temp_check_values["nvd.nist.gov"] = 0
                    temp_check_values["nvd_id"] = None

                """Identify any JSONs with a cisa object"""
                if '\'cisa.gov\':' in str(data):
                    temp_check_values["cisa.gov"] = 1
                    try:
                        temp_check_values["cisa_id"] = data["namespaces"]["cisa.gov"]["cveID"]
                    except:
                        temp_check_values["cisa_id"] = None
                else:
                    temp_check_values["cisa.gov"] = 0
                    temp_check_values["cisa_id"] = None

                """Identify any JSONs with a gitlab.com object"""
                if '\'gitlab.com\':' in str(data):
                    temp_check_values["gitlab.com"] = 1
                    try:
                        temp_check_values["gitlab_id"] = data["namespaces"]["gitlab.com"]["advisories"][0]["identifier"]
                    except:
                        temp_check_values["gitlab_id"] = None
                else:
                    temp_check_values["gitlab.com"] = 0
                    temp_check_values["gitlab_id"] = None

                """Checking for GSD JSONs with the following key"""
                if "github.com/kurtseifried:582211" in str(data):
                    temp_check_values["github.com/kurtseifried:582211"] = 1
                else:
                    temp_check_values["github.com/kurtseifried:582211"] = 0

                master_checklist = pd.concat([master_checklist, temp_check_values])

                f.close()

        schema = builder.to_schema()["properties"]

        """Save complete schema"""
        with open("./data/schemas/gsd_complete_schema.json", "w") as schema_file:
            json.dump(schema, schema_file, indent=4, sort_keys=True)

        master_checklist.to_csv(f"./data/gsd_counts.csv", encoding='utf-8', index=False)

    return schema, master_checklist


if __name__ == '__main__':
    start = time.time()

    """Get GSD Entries & the update time"""
    gsd_list, gsd_update_time = get_gsd_list()

    """Figure for GSD Entries by Year"""
    # visualize_gsd(gsd_list, gsd_update_time)

    """Generate Schemas for GSD"""
    complete_schema, gsd_df = generate_complete_gsd_schema(gsd_list)

    """============================================================================================================"""
    """============================================================================================================"""

    """GSD SCHEMA"""
    schema_gsd = complete_schema["GSD"]
    # Save GSD Schema
    with open("./data/schemas/schema_gsd_object.json", "w") as write_file:
        json.dump(schema_gsd, write_file, indent=4, sort_keys=True)

    # Find instances when the GSD object is missing
    example_missing_gsd = gsd_df[gsd_df["missingGSD"] == 1].sort_values("gsd_path")
    print("Missing GSD:", example_missing_gsd["api"].values.tolist())

    # Find instances when entries only contain a GSD object
    print("Only GSD:")
    example_only_gsd = gsd_df[(gsd_df["GSD"] == 1) &
                                        (gsd_df["cisa.gov"] == 0) &
                                        (gsd_df["github.com/kurtseifried:582211"] == 0) &
                                        (gsd_df["gitlab.com"] == 0) &
                                        (gsd_df["nvd.nist.gov"] == 0) &
                                        (gsd_df["cve.org"] == 0) &
                                        (gsd_df["OSV"] == 0)].sort_values("gsd_path")
    for each in example_only_gsd["api"].values.tolist():
        print(each)

    """============================================================================================================"""
    """============================================================================================================"""

    """OSV SCHEMA"""
    schema_osv = complete_schema["OSV"]

    # Save OSV Schema
    with open("./data/schemas/schema_osv.json", "w") as write_file:
        json.dump(schema_osv, write_file, indent=4, sort_keys=True)

    # OSV examples
    example_osv = gsd_df[gsd_df["OSV"] == 1]
    # print two random OSV examples
    print("OSV examples:")
    for each in example_osv["api"].sample(2).values.tolist():
        print(each)

    """============================================================================================================"""
    """============================================================================================================"""

    """cisa.gov SCHEMA"""
    schema_cisa = complete_schema["namespaces"]["properties"]["cisa.gov"]

    # CISA examples
    example_cisa = gsd_df[gsd_df["cisa.gov"] == 1]
    # print two random CISA examples
    print("cisa.gov examples:")
    for each in example_cisa["api"].sample(2).values.tolist():
        print(each)

    # Save CISA Schema
    with open("./data/schemas/schema_cisa.json", "w") as write_file:
        json.dump(schema_cisa, write_file, indent=4, sort_keys=True)

    """============================================================================================================"""
    """============================================================================================================"""

    """cve.org SCHEMA"""
    schema_cve_org = complete_schema["namespaces"]["properties"]["cve.org"]

    # CVE.org examples
    example_cve_org = gsd_df[gsd_df["cve.org"] == 1]
    # print two random CISA examples
    print("cve.org examples:")
    for each in example_cve_org["api"].sample(2).values.tolist():
        print(each)

    # Save CISA Schema
    with open("./data/schemas/schema_cve_org.json", "w") as write_file:
        json.dump(schema_cve_org, write_file, indent=4, sort_keys=True)

    """============================================================================================================"""
    """============================================================================================================"""

    """kurt SCHEMA"""
    schema_kurt = complete_schema["namespaces"]["properties"]["github.com/kurtseifried:582211"]
    example_kurt = gsd_df[gsd_df["github.com/kurtseifried:582211"] == 1].sort_values("gsd_path")
    print("github.com/kurtseifried:582211")
    for each in example_kurt["api"].values.tolist():
        print(each)

    """============================================================================================================"""
    """============================================================================================================"""

    """gitlab.com SCHEMA"""
    schema_gitlab = complete_schema["namespaces"]["properties"]["gitlab.com"]
    # gitlab examples
    example_gitlab = gsd_df[gsd_df["gitlab.com"] == 1]
    # print two random CISA examples
    print("gitlab.com examples:")
    for each in example_gitlab["api"].sample(2).values.tolist():
        print(each)

    # Save gitlab.com Schema
    with open("./data/schemas/schema_gitlab.json", "w") as write_file:
        json.dump(schema_gitlab, write_file, indent=4, sort_keys=True)

    """============================================================================================================"""
    """============================================================================================================"""

    """nvd.nist.gov SCHEMA"""
    schema_nvd = complete_schema["namespaces"]["properties"]["nvd.nist.gov"]

    # nvd examples
    example_nvd = gsd_df[gsd_df["nvd.nist.gov"] == 1]
    # print two random NVD examples
    print("nvd.nist.gov examples:")
    for each in example_nvd["api"].sample(2).values.tolist():
        print(each)

    # Save gitlab.com Schema
    with open("./data/schemas/schema_nvd.json", "w") as write_file:
        json.dump(schema_nvd, write_file, indent=4, sort_keys=True)

    """============================================================================================================"""
    """============================================================================================================"""

    """overlay SCHEMA"""
    schema_overlay = complete_schema["overlay"]
    example_overlay = gsd_df[gsd_df["overlay"] == 1].sort_values("gsd_path")
    print("Overlay: ", example_overlay["api"].values.tolist())


    print("done")
