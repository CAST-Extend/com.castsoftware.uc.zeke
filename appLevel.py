'''
Created on Oct 15, 2019

@author: JGD
'''
import cast_upgrade_1_6_16 # @UnusedImport
from cast.application import ApplicationLevelExtension, create_link
from cast.application import CustomObject # @UnresolvedImport
import logging

class ApplicationExtension(ApplicationLevelExtension):
    def __init__(self):
        self.missingJCLsSection = None
        self.missingJCLCount = 0;
        self.linkCount = 0;
    
    def start_application(self, application):
        logging.info('Starting ZEKE Processing (start application)...')               

    #new step to create objects in 1.6.0
    def end_application_create_objects(self, application):
        logging.info('Starting ZEKE Processing (end application create objects)...')
        
        for o in application.search_objects(name='Missing JCLs', category='ZEKESection'):
            self.missingJCLsSection = o
            break
        
        logging.info('Create links from ZEKE Jobs to JCLs');
        for job in application.search_objects(category='ZEKEJob'):
        #for job in application.get_files(['ZEKEJob']):             
            # check if file is analyzed source code, or if it generated (Unknown)
            #if not job.get_path():
            #    continue
            
            logging.info('Looking for JCL %s' % job.name)
            jclFound = False
            for jcl in application.search_objects(name=job.name, category='CAST_JCL_CatalogedJob'):
            #for jcl in application.get_files(['CAST_JCL_CatalogedJob']):             
                # check if file is analyzed source code, or if it generated (Unknown)
                #if not jcl.get_path():
                #    continue
                
                if job.name == jcl.name:
                    create_link('callLink', job, jcl)
                    self.linkCount += 1
                    jclFound = True
                    break
            
            if not jclFound:
                jclObject = CustomObject()
                jclObject.set_name(job.name)
                jclObject.set_fullname("Missing JCLs/%s" % (job.name))
                jclObject.set_type('CAST_JCL_CatalogedJob')
                jclObject.set_parent(self.missingJCLsSection)
                jclObject.save()
                self.missingJCLCount += 1
                create_link('callLink', job, jclObject)
                self.linkCount += 1
    
    def end_application(self, application):
        logging.info('Starting ZEKE Processing (end application)...')
        
        logging.info("ZEKE Analysis Completed")
        logging.info("Statistics")
        logging.info("----------")
        logging.info("Missing JCLs: %d" % self.missingJCLCount)
        logging.info("Links: %d" % self.linkCount)
        