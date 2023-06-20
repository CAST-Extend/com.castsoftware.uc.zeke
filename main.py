import cast_upgrade_1_6_16 # @UnusedImport
import cast.analysers.ua
from cast.analysers import log, Bookmark, create_link
import os
import re

class ZekeSrcFile(cast.analysers.ua.Extension):
    def __init__(self):         
        self.jobs = {}
        self.events = {}
        self.eventsWhen = {}
        self.linkCount = 0
        self.project = None
        self.missingJCLsSection = None
        # do we have the correct UA selected or not
        self.active = True
        # default extension list (for unit tests)
        self.extensions = ['.zeke']
            
    def start_analysis(self):
        log.info("Starting ZEKE Analysis...")
        # resistant (for unit tests)
        try:
            options = cast.analysers.get_ua_options()               #@UndefinedVariable dynamically added
            if not 'ZEKE' in options:
                # SQLScript language not selected : inactive
                self.active = False
            else:
                # options :
                self.extensions = options['ZEKE'].extensions
        except:
            pass        
    
    def start_file(self, file):
        if not self.active:
            return # no need to do anything
        
        filepath = file.get_path().lower()
        #_, <- because we're discarding the first part of the splitext
        _, ext = os.path.splitext(filepath)
 
        if not ext in self.extensions:
            return

        log.info("Parsing file %s..." % filepath)
        self.project = file.get_project()
        
        lineNb = 0
        
        eventNumber = ''
        eventLineStart = -1
        description = ''
        eventObject = None
        self.create_missing_jcl_section()
        activeFields=-1
        with open(file.get_path(), 'r') as f:
            for line in f:
                lineNb +=1
                
                if line.strip() == 'LIST EVENT ACTIVE FIELD=(EV,ENAME,JOB,APPL,GRO,SYSTEM,SCHED,TEXT)':
                    activeFields=1
                    log.info("Mode 1: EV,ENAME,JOB,APPL,GRO,SYSTEM,SCHED,TEXT")

                if line.strip() == 'LIST EVENT ACTIVE FIELD=(EV,ENAME,CALID,CONTROL)':
                    activeFields=2
                    log.info("Mode 2: EV,ENAME,CALID,CONTROL")

                #lines to skip
                matchObj = re.search('^(REPORT|EVENT|NUMBER)[\s]', line)
                if matchObj:
                    continue
                
                if re.match('[0-9]+', line[0:6].strip()):
                    if eventObject: #if there's a current event, save its description before handling next
                        eventObject.save_property('ZEKEProperties.description', description)                       
                        eventObject.save_position(Bookmark(file, eventLineStart, 0, lineNb-1, -1))

                        matchObj = re.search('WHEN[\s]+\(([^)]+)\)', description)
                        if matchObj:
                            self.eventsWhen[eventObject.name]=matchObj.group(1)
                            #log.info("%s - %s" % (eventObject.name, matchObj.group(1)))
                    
                    eventLineStart = lineNb
                    eventNumber = line[0:6].strip()
                    eventName = line[7:19].strip()

                    #log.info('[%s] %s - %s' % (eventNumber, eventName, jobName))
                    #Save Event Object
                    if eventName == '':
                        log.warning("line %d - Unable to extract event name" % lineNb)
                    else:
                        eventObject = cast.analysers.CustomObject()
                        eventObject.set_name(eventName)
                        eventObject.set_fullname("%s/%s" % (filepath, eventName))
                        eventObject.set_type('ZEKEEvent')
                        eventObject.set_parent(file)
                        eventObject.save()
                        self.events[eventName] = (eventObject)

                        if activeFields == 1:
                            jobName = line[20:28].strip()
                            applId = line[29:37].strip()
                            grpId = line[38:41].strip()
                            system = line[42:50].strip()
                            schedTime = line[51:56].strip()
                            description = line[57:].strip()
                            #Link to Job Object (create if not exists)
                            if jobName != '':
                                jobObject = None
                                if jobName in self.jobs:
                                    jobObject = self.jobs[jobName]

                                if jobObject is None:  
                                    jobObject = cast.analysers.CustomObject()
                                    jobObject.set_name(jobName)
                                    jobObject.set_fullname("%s/%s" % (filepath, jobName))
                                    jobObject.set_type('ZEKEJob')
                                    jobObject.set_parent(file)
                                    jobObject.save()
                                    self.jobs[jobName] = jobObject
                                    jobObject.save_position(Bookmark(file, lineNb, 0, lineNb, -1))
                                
                                create_link('referLink', eventObject, jobObject, Bookmark(file, lineNb, 20, lineNb, 28))
                                self.linkCount+=1

                            #save properties
                            eventObject.save_property('ZEKEProperties.applId', applId)
                            eventObject.save_property('ZEKEProperties.grpId', grpId)
                            eventObject.save_property('ZEKEProperties.system', system)
                            eventObject.save_property('ZEKEProperties.schedTime', schedTime)
                        
                        if activeFields == 2:
                            calid = line[20:28].strip()
                            control = line[30:].strip()
                            description = ''

                            eventObject.save_property('ZEKEProperties.calid', calid)
                            eventObject.save_property('ZEKEProperties.control', control)

                        #if activeFields == -1: Nothing else

                else: #continuation of an existing job -> append to jobDscr
                    if eventNumber != '':
                        if line.strip() != '':
                            description = "%s\n%s" % (description, line.strip()) 
    
    def create_section(self, file, filepath, sectionName):
        section = cast.analysers.CustomObject()
        section.set_name(sectionName)
        section.set_fullname(sectionName)
        section.set_type('ZEKESection')
        section.set_parent(file)
        section.save()
        return section
    
    def create_missing_jcl_section(self):
        if not self.missingJCLsSection:            
            self.missingJCLsSection = cast.analysers.CustomObject()
            self.missingJCLsSection.set_name('Missing JCLs')
            self.missingJCLsSection.set_fullname('Missing JCLs')
            self.missingJCLsSection.set_type('ZEKESection')
            self.missingJCLsSection.set_parent(self.project)
            self.missingJCLsSection.save()
    
    def end_analysis(self):
        if not self.active:
            return # no need to do anything
        
        minEventLen = 10
        for eventName, event in self.events.items():
            minEventLen = min(len(eventName), minEventLen)
        #log.debug("Min Event Name Length: %d" % minEventLen)

        log.debug("Linking - %d events with WHEN clause..." % len(self.eventsWhen))
        for eventName, whenClause in self.eventsWhen.items():
            #log.info("%s - %s" % (eventName, whenClause))
            eventObject = None
            for match in re.findall('[\s]+([\w]+)', whenClause):
                #log.info("%s - %s" % (eventName, match))
                if len(match) >= minEventLen: # anything else is a keyword AND/OR/EOE/EOG/etc..
                    targetEvent = None
                    if match in self.events:
                        targetEvent = self.events[match]

                    if targetEvent is not None:
                        if eventObject is None:
                            if eventName in self.events:
                                eventObject = self.events[eventName]
                        
                        create_link('fireLink', eventObject, targetEvent)
                        self.linkCount+=1
                            
        log.info("ZEKE Analysis Completed")
        log.info("Statistics")
        log.info("----------")
        log.info("Events: %d" % len(self.events))
        log.info("Jobs: %d" % len(self.jobs))
        log.info("Links: %d" % self.linkCount)
