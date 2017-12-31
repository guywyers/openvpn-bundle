#ifndef PROFILE_TRANSFORM_H
#define PROFILE_TRANSFORM_H

#include <stdio.h>

#include "profile.h"

extern bool TransformProfile(FILE* from, FILE* to);

extern bool TransformToAppleProfile(FILE* from, FILE* to, profile_info * profile);


#endif // !PROFILE_TRANSFORM_H

