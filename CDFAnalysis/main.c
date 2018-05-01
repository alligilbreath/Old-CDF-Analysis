#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define MAX_SAMPLES  50000
#define MAX_EVENTS 20
#define WINDOW_SIZE 20
#define WINDOW_STRIDE 5
#define DIVISION_OF_DATA 1.0 / 3

typedef struct EventData_struct
{
    int numSamples;
    long int timingData[MAX_SAMPLES];
    long int trainingData1[MAX_SAMPLES];
    long int trainingData2[MAX_SAMPLES];
    long int evaluationData[MAX_SAMPLES];
    int minBoundary[WINDOW_SIZE];
    int maxBoundary[WINDOW_SIZE];
    float threshold;
    float falsePositiveRate;
}
EventData;

//similar calculation as threshold where max amount of outsiders pers window / WINDOW_SIZE * 1.0 * 100
float CalcFalsePositiveRate(EventData *currentEvent)
{
    int currentWindow[WINDOW_SIZE];
    printf("-----------------------------\n");
    int numOutsiders = 0;
    int numFlagged = 0;
    int numWindows = 0;
    for (int i = 0; i < (*currentEvent).numSamples * DIVISION_OF_DATA; i += WINDOW_STRIDE) {
        //populate the currentWindow array
        for (int j = 0; j < WINDOW_SIZE && i < (*currentEvent).numSamples; j++)
        {
            currentWindow[j] = (*currentEvent).evaluationData[i + j];
            //i++;
        }
        //insertion sort to sort currentWindow
        int temp = 0;
        int j = 0;
        for (int k = 1; k < WINDOW_SIZE; k++)
        {
            temp = currentWindow[k];
            j = k - 1;
            
            /* Move elements of arr[0..i-1], that are
             greater than key, to one position ahead
             of their current position */
            while (j >= 0 && currentWindow[j] > temp)
            {
                currentWindow[j + 1] = currentWindow[j];
                j--;
            }
            currentWindow[j + 1] = temp;
        }
        numWindows++;
        //now check if each element is less/more than max/min boundaries multiplied by the threshold
        for (j = 0; j < WINDOW_SIZE; j++)
        {
            if (currentWindow[j] == 74799999)
            {
                printf("Found it\n");
            }
            
            if (currentWindow[j] < ((*currentEvent).minBoundary[j]) && currentWindow[j] != 0) //!0 is from when we put 0s in tD1 in main
            {
                numOutsiders++;
            }
            else if (currentWindow[j] > ((*currentEvent).maxBoundary[j]) && currentWindow[j] != 0)
            {
                numOutsiders++;
            }
        }
        
        //printf("Num outsiders: %d", numOutsiders);
        //printf("NumOutsiders Percentage: %d\n", numOutsiders / (WINDOW_SIZE * 1.0) * 100);
        //printf("Threshold: %f", (*currentEvent).threshold);
        
        if ((numOutsiders / (WINDOW_SIZE * 1.0)) * 100 > (*currentEvent).threshold)
        {
            numFlagged++;
        }
        
        numOutsiders = 0;
    }
    printf("Number flagged: %d", numFlagged);
    return numFlagged / (numWindows * 1.0);
}

// (calc probability of malware that takes in two windows (currentwindow and min and max boundaries) then calculating the probability of malware
//probability of malware is used in threshold and false positive
//trainingData2 and threshold
float CalcThreshold(EventData *currentEvent)
{
    int currentWindow[WINDOW_SIZE];
    int numOutsiders = 0;
    int maxOutsiders = 0;
    for (int i = 0; i < (*currentEvent).numSamples * DIVISION_OF_DATA; i += WINDOW_STRIDE) {
        //populate the currentWindow array
        for (int j = 0; j < WINDOW_SIZE && i < (*currentEvent).numSamples; j++)
        {
            currentWindow[j] = (*currentEvent).trainingData2[i + j];
            //i++;
        }
        //insertion sort to sort currentWindow
        int temp = 0;
        int j = 0;
        for (int k = 1; k < WINDOW_SIZE; k++)
        {
            temp = currentWindow[k];
            j = k - 1;
            
            /* Move elements of arr[0..i-1], that are
             greater than key, to one position ahead
             of their current position */
            while (j >= 0 && currentWindow[j] > temp)
            {
                currentWindow[j + 1] = currentWindow[j];
                j--;
            }
            currentWindow[j + 1] = temp;
        }
        //now check if the element is less/more for min and max boundaries
        for (j = 0; j < WINDOW_SIZE; j++)
        {
            if (currentWindow[j] < (*currentEvent).minBoundary[j] && currentWindow[j] != 0) //!0 is from when we put 0s in tD1 in main
            {
                numOutsiders++;
            }
            else if (currentWindow[j] > (*currentEvent).maxBoundary[j] && currentWindow[j] != 0)
            {
                numOutsiders++;
            }
        }
        
        if (numOutsiders > maxOutsiders)
        {
            maxOutsiders = numOutsiders;
        }
        
        numOutsiders = 0;
        
    }
    return (maxOutsiders / (WINDOW_SIZE * 1.0)) * 100;
}
//minCDF are the lowest values of each window
//maxCDF are the highest values of each window
void CalcBoundaries(EventData *currentEvent)
{
    int currentWindow[WINDOW_SIZE];
    
    //populate the min highest int value
    //populate the max with 0s
    for (int i = 0; i < WINDOW_SIZE; i++)
    {
        (*currentEvent).minBoundary[i] = INT_MAX;
        (*currentEvent).maxBoundary[i] = 0;
    }
    //outside loop needed to keep doing the j for loop and to use window_stride
    for (int i = 0; i < (*currentEvent).numSamples * DIVISION_OF_DATA; i += WINDOW_STRIDE) {
        //populate the currentWindow array
        for (int j = 0; j < WINDOW_SIZE && i < (*currentEvent).numSamples; j++)
        {
            currentWindow[j] = (*currentEvent).trainingData1[i+j];
            //i++;
        }
        //insertion sort to sort currentWindow
        int temp = 0;
        int j = 0;
        for (int k = 1; k < WINDOW_SIZE; k++)
        {
            temp = currentWindow[k];
            j = k - 1;
            
            /* Move elements of arr[0..i-1], that are
             greater than key, to one position ahead
             of their current position */
            while (j >= 0 && currentWindow[j] > temp)
            {
                currentWindow[j + 1] = currentWindow[j];
                j--;
            }
            currentWindow[j + 1] = temp;
        }
        //now check if the element is less/more for min and max boundaries
        for (int j = 0; j < WINDOW_SIZE; j++)
        {
            if (currentWindow[j] < (*currentEvent).minBoundary[j] && currentWindow[j] != 0) //!0 is from when we put 0s in tD1 in main
            {
                (*currentEvent).minBoundary[j] = currentWindow[j];
            }
            else if (currentWindow[j] > (*currentEvent).maxBoundary[j]) {
                (*currentEvent).maxBoundary[j] = currentWindow[j];
            }
        }
        
        
        
    }
}


int main(void)
{
    FILE *normalFile;
    int numNormalEntries = 0;
    int numEvents = 0;
    
    normalFile = fopen("T4_normal.txt", "r");
    int chosenEvent = 0;
    EventData allEvents[MAX_EVENTS];
    if (normalFile == NULL)
    {
        printf("The file is NULL.\n");
    }
    else
    {
        char delims[] = " ";
        //char *line;
        char buffer[1000];
        char line[1000];
        
        for (int i = 0; i < MAX_EVENTS; i++) {
            allEvents[i].numSamples = 0;
        }
        fgets(buffer, sizeof(buffer), normalFile);
        strcpy(line, buffer);
        char *result = NULL;
        result = strtok(line, delims);
        while (result != NULL) {
            numEvents++;
            result = strtok(NULL, delims);
        }
        numEvents--; //to account for the extra in strtok
        
        int currentEvent = 0;
        long int currentSample = 0;
        strcpy(line, buffer);
        while (!feof(normalFile))
        {
            result = strtok(line, delims); //make result the first line again
            while (result != NULL) {
                sscanf(result, "%ld", &currentSample);
                if (currentSample > 0)
                {
                    allEvents[currentEvent].timingData[allEvents[currentEvent].numSamples] = currentSample;
                    allEvents[currentEvent].numSamples++;
                    //printf("%d ", allEvents[currentEvent].timingData[allEvents[currentEvent].numSamples]);
                    //system("pause");
                }
                currentEvent++;
                //printf("\n");
                result = strtok(NULL, delims);
            }
            
            fgets(line, sizeof(line), normalFile);
            currentEvent = 0;
        }
        //print event number, first five, last five
        //to fix min problem, have to populate trainingData1 with 0s
        for (int i = 0; i < numEvents + 1; i++)
        {
            for (int j = 0; j < MAX_SAMPLES; j++)
            {
                allEvents[i].trainingData1[j] = 0;
                allEvents[i].trainingData2[j] = 0;
                allEvents[i].evaluationData[j] = 0;
            }
        }
        for (int i = 0; i < numEvents + 1; i++)
        {
            for (int j = 0; j < allEvents[i].numSamples * DIVISION_OF_DATA; j++)
            {
                allEvents[i].trainingData1[j] = allEvents[i].timingData[j];
            }
        }
        
        for (int i = 0; i < numEvents + 1; i++)
        {
            CalcBoundaries(&allEvents[i]);
        }
        
        for (int i = 0; i < numEvents + 1; i++)
        {
            int startOffset = allEvents[i].numSamples * DIVISION_OF_DATA;
            
            for (int j = 0; j < allEvents[i].numSamples * DIVISION_OF_DATA; j++)
            {
                allEvents[i].trainingData2[j] = allEvents[i].timingData[j+ startOffset];
            }
        }
        
        for (int i = 0; i < numEvents + 1; i++)
        {
            allEvents[i].threshold = CalcThreshold(&allEvents[i]);
        }
        
        for (int i = 0; i < numEvents + 1; i++)
        {
            int startingOffset = allEvents[i].numSamples * DIVISION_OF_DATA * 2;
            for (int j = 0; j < allEvents[i].numSamples; j++)
            {
                
                allEvents[i].evaluationData[j] = allEvents[i].timingData[j + startingOffset];
                
            }
        }
        //allEvents[1].maxBoundary[19] = 401;
        for (int i = 0; i < numEvents + 1; i++)
        {
            allEvents[i].falsePositiveRate = CalcFalsePositiveRate(&allEvents[i]);
        }
    }
    
    //printf("Number we changed: ", allEvents[0].timingData[35919]);
    
    fclose(normalFile);
    return 0;
}
