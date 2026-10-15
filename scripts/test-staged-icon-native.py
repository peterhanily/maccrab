#!/usr/bin/python3
"""Bounded data-only ImageIO/NSImage icon parity gate; never edits source/stage.

The production compressor's pure prepare() creates a private candidate from the
pinned original. Independent input/output pins precede native decoding. Inputs,
fixed native source, executable and diagnostics remain in a fresh mode0700
temporary directory printed in the result. No NSApplication, drawing, window,
permission, installed app, URL loader, or network operation is used.
Run with no arguments under a 120-second outer process deadline.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import tempfile
import time

BASE = Path(__file__).resolve().parent
ORIGINAL = BASE.parent / 'Sources/MacCrabApp/Resources/AppIcon.icns'
ORIGINAL_SHA256 = 'ff369902730ec16f2464160b814cd9807fde38be4612e510457c4d9fa89398c0'
CANDIDATE_SHA256 = 'bf6efb327d49ddc768c2134b8f93f109b3a957faa06b5abb5fc4d30335b8becf'
MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = 64 * 1024
NATIVE_SOURCE = r'''
#import <Foundation/Foundation.h>
#import <AppKit/NSImage.h>
#import <AppKit/NSBitmapImageRep.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <string.h>

static const size_t MaxDimension = 2048;
static const size_t MaxPixels = 32 * 1024 * 1024;
static BOOL Same(id a, id b) { return a == b || (a && b && [a isEqual:b]); }
static BOOL SameCF(CFTypeRef a, CFTypeRef b) { return a == b || (a && b && CFEqual(a, b)); }

static BOOL ImageEqual(CGImageRef a, CGImageRef b, size_t *bytes) {
  if (!a || !b) return NO;
  size_t width = CGImageGetWidth(a), height = CGImageGetHeight(a), row = CGImageGetBytesPerRow(a);
  if (!width || !height || width > MaxDimension || height > MaxDimension ||
      row > MaxPixels / height || !row || width != CGImageGetWidth(b) ||
      height != CGImageGetHeight(b) || row != CGImageGetBytesPerRow(b) ||
      CGImageGetBitsPerComponent(a) != CGImageGetBitsPerComponent(b) ||
      CGImageGetBitsPerPixel(a) != CGImageGetBitsPerPixel(b) ||
      CGImageGetBitmapInfo(a) != CGImageGetBitmapInfo(b) ||
      CGImageGetAlphaInfo(a) != CGImageGetAlphaInfo(b) ||
      CGImageGetRenderingIntent(a) != CGImageGetRenderingIntent(b) ||
      CGImageGetShouldInterpolate(a) != CGImageGetShouldInterpolate(b) ||
      CGImageIsMask(a) != CGImageIsMask(b)) return NO;
  CGColorSpaceRef ac = CGImageGetColorSpace(a), bc = CGImageGetColorSpace(b);
  if (!ac || !bc || CGColorSpaceGetModel(ac) != CGColorSpaceGetModel(bc) ||
      CGColorSpaceGetNumberOfComponents(ac) != CGColorSpaceGetNumberOfComponents(bc) ||
      !SameCF(CGColorSpaceGetName(ac), CGColorSpaceGetName(bc))) return NO;
  CFDataRef ap = CGColorSpaceCopyICCData(ac), bp = CGColorSpaceCopyICCData(bc);
  BOOL profileEqual = SameCF(ap, bp);
  if (ap) CFRelease(ap);
  if (bp) CFRelease(bp);
  if (!profileEqual) return NO;
  const CGFloat *ad = CGImageGetDecode(a), *bd = CGImageGetDecode(b);
  size_t components = CGColorSpaceGetNumberOfComponents(ac);
  if (components > 16 || ((ad == NULL) != (bd == NULL)) ||
      (ad && memcmp(ad, bd, components * 2 * sizeof(CGFloat)))) return NO;
  CGDataProviderRef av = CGImageGetDataProvider(a), bv = CGImageGetDataProvider(b);
  if (!av || !bv) return NO;
  CFDataRef ax = CGDataProviderCopyData(av), bx = CGDataProviderCopyData(bv);
  BOOL equal = ax && bx && CFDataGetLength(ax) >= (CFIndex)(row * height) &&
    CFDataGetLength(ax) <= (CFIndex)MaxPixels && SameCF(ax, bx);
  if (equal) *bytes += (size_t)CFDataGetLength(ax);
  if (ax) CFRelease(ax);
  if (bx) CFRelease(bx);
  return equal;
}

static NSMutableDictionary *SourceProperties(CGImageSourceRef source, NSUInteger length) {
  NSDictionary *properties = CFBridgingRelease(CGImageSourceCopyProperties(source, NULL));
  if (!properties) return nil;
  NSMutableDictionary *result = [properties mutableCopy];
  id size = result[(__bridge NSString *)kCGImagePropertyFileSize];
  // Container size is expected to change; verify it, never broadly filter metadata.
  if (size && (![size isKindOfClass:[NSNumber class]] || [size unsignedLongLongValue] != length)) return nil;
  [result removeObjectForKey:(__bridge NSString *)kCGImagePropertyFileSize];
  return result;
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc != 3) return 2;
    NSData *a = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
    NSData *b = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[2]]];
    if (!a || !b || a.length > 16 * 1024 * 1024 || b.length > 16 * 1024 * 1024) return 3;
    CGImageSourceRef as = CGImageSourceCreateWithData((__bridge CFDataRef)a, NULL);
    CGImageSourceRef bs = CGImageSourceCreateWithData((__bridge CFDataRef)b, NULL);
    if (!as || !bs) return 4;
    if (!SameCF(CGImageSourceGetType(as), CFSTR("com.apple.icns")) ||
        !SameCF(CGImageSourceGetType(as), CGImageSourceGetType(bs)) ||
        CGImageSourceGetStatus(as) != kCGImageStatusComplete ||
        CGImageSourceGetStatus(bs) != kCGImageStatusComplete) return 5;
    size_t count = CGImageSourceGetCount(as), bytes = 0;
    if (!count || count > 32 || count != CGImageSourceGetCount(bs)) return 6;
    NSDictionary *ap = SourceProperties(as, a.length), *bp = SourceProperties(bs, b.length);
    if (!ap || !bp || !Same(ap, bp)) return 7;
    NSMutableArray *dimensions = [NSMutableArray array];
    BOOL found1024 = NO;
    for (size_t index = 0; index < count; index++) {
      @autoreleasepool {
        NSDictionary *left = CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(as, index, NULL));
        NSDictionary *right = CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(bs, index, NULL));
        NSNumber *width = left[(__bridge NSString *)kCGImagePropertyPixelWidth];
        NSNumber *height = left[(__bridge NSString *)kCGImagePropertyPixelHeight];
        if (!left || !right || !Same(left, right) || ![width isKindOfClass:[NSNumber class]] ||
            ![height isKindOfClass:[NSNumber class]] || width.unsignedLongLongValue < 1 ||
            height.unsignedLongLongValue < 1 || width.unsignedLongLongValue > MaxDimension ||
            height.unsignedLongLongValue > MaxDimension) return 8;
        CGImageRef ai = CGImageSourceCreateImageAtIndex(as, index, NULL);
        CGImageRef bi = CGImageSourceCreateImageAtIndex(bs, index, NULL);
        BOOL equal = ImageEqual(ai, bi, &bytes);
        if (ai) CGImageRelease(ai);
        if (bi) CGImageRelease(bi);
        if (!equal || CGImageSourceGetStatusAtIndex(as, index) != kCGImageStatusComplete ||
            CGImageSourceGetStatusAtIndex(bs, index) != kCGImageStatusComplete) return 9;
        [dimensions addObject:@[width, height]];
        found1024 |= width.unsignedLongLongValue == 1024 && height.unsignedLongLongValue == 1024;
      }
    }
    CFRelease(as);
    CFRelease(bs);
    if (!found1024) return 10;
    NSImage *an = [[NSImage alloc] initWithData:a], *bn = [[NSImage alloc] initWithData:b];
    if (!an || !bn || !NSEqualSizes(an.size, bn.size) || an.template != bn.template) return 11;
    NSArray<NSImageRep *> *ar = an.representations, *br = bn.representations;
    if (!ar.count || ar.count > 32 || ar.count != br.count) return 12;
    NSMutableArray *nativeDimensions = [NSMutableArray array];
    NSArray *keys = @[NSImageColorSyncProfileData, NSImageGamma, NSImageInterlaced,
      NSImageCompressionMethod, NSImageCompressionFactor, NSImageDitherTransparency,
      NSImageFallbackBackgroundColor,
      NSImageRGBColorTable, NSImageFrameCount, NSImageCurrentFrame, NSImageCurrentFrameDuration,
      NSImageLoopCount, NSImageProgressive, NSImageEXIFData, NSImageIPTCData];
    for (NSUInteger index = 0; index < ar.count; index++) {
      @autoreleasepool {
        NSImageRep *left = ar[index], *right = br[index];
        if (![left isKindOfClass:[NSBitmapImageRep class]] || ![right isKindOfClass:[NSBitmapImageRep class]] ||
            left.class != right.class || !NSEqualSizes(left.size, right.size) ||
            left.pixelsWide != right.pixelsWide || left.pixelsHigh != right.pixelsHigh ||
            left.bitsPerSample != right.bitsPerSample || left.hasAlpha != right.hasAlpha ||
            left.opaque != right.opaque || left.layoutDirection != right.layoutDirection ||
            !Same(left.colorSpaceName, right.colorSpaceName)) return 13;
        NSBitmapImageRep *al = (NSBitmapImageRep *)left, *bl = (NSBitmapImageRep *)right;
        if (al.planar != bl.planar || al.samplesPerPixel != bl.samplesPerPixel ||
            al.bitsPerPixel != bl.bitsPerPixel || al.bytesPerRow != bl.bytesPerRow ||
            al.bytesPerPlane != bl.bytesPerPlane || al.numberOfPlanes != bl.numberOfPlanes ||
            al.bitmapFormat != bl.bitmapFormat || !ImageEqual(al.CGImage, bl.CGImage, &bytes)) return 14;
        for (NSString *key in keys) if (!Same([al valueForProperty:key], [bl valueForProperty:key])) return 15;
        [nativeDimensions addObject:@[@(left.pixelsWide), @(left.pixelsHigh)]];
      }
    }
    NSDictionary *result = @{ @"imageio_representations": @(count), @"nsimage_representations": @(ar.count),
      @"imageio_dimensions": dimensions, @"nsimage_dimensions": nativeDimensions,
      @"compared_pixel_bytes": @(bytes), @"imageio_properties_equal": @YES,
      @"native_profiles_equal": @YES, @"native_pixels_equal": @YES,
      @"excluded_global_property": @"FileSize (validated against each input length)" };
    NSError *error = nil;
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:&error];
    if (!encoded || error || encoded.length > 65536) return 16;
    if (fwrite(encoded.bytes, 1, encoded.length, stdout) != encoded.length || fputc('\n', stdout) == EOF) return 17;
  }
  return 0;
}
'''


def require(condition, code):
    if not condition:
        raise ValueError(code)


def read_input(path):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'input_not_canonical')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 8 <= before.st_size <= MAX_INPUT,
                'input_not_bounded_regular_file')
        chunks, length = [], 0
        while length <= MAX_INPUT:
            chunk = os.read(fd, min(65536, MAX_INPUT + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(length == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
                'input_changed')
        return b''.join(chunks)
    finally:
        os.close(fd)


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)


def bounded_process(command, seconds, directory, stem):
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TMPDIR': str(directory)}
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, start_new_session=True)
    selector = selectors.DefaultSelector()
    outputs = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + seconds
    try:
        for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map():
            require(time.monotonic() < deadline, stem + '_timeout')
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                outputs[key.data].extend(chunk)
                require(len(outputs[key.data]) <= MAX_OUTPUT, stem + '_output_exceeded')
        status = process.wait(timeout=max(.001, deadline - time.monotonic()))
        require(status == 0 and not outputs['stderr'], stem + '_error_or_warning')
        return bytes(outputs['stdout'])
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
        # Retain bounded partial diagnostics on timeouts/output-bound failures too.
        exclusive(directory / (stem + '.stdout'), bytes(outputs['stdout'][:MAX_OUTPUT]))
        exclusive(directory / (stem + '.stderr'), bytes(outputs['stderr'][:MAX_OUTPUT]))


def main():
    original = read_input(ORIGINAL)
    require(hashlib.sha256(original).hexdigest() == ORIGINAL_SHA256, 'source_pin_mismatch')
    specification = importlib.util.spec_from_file_location('native_icon_compressor', BASE / 'compress-staged-icon.py')
    compressor = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(compressor)
    candidate = compressor.prepare(original)  # Pure bytes-only production function; no staging CLI.
    require(len(candidate) == 886141 and hashlib.sha256(candidate).hexdigest() == CANDIDATE_SHA256,
            'candidate_pin_mismatch')
    run = Path(tempfile.mkdtemp(prefix='maccrab-native-icon-parity-')).resolve()
    os.chmod(run, 0o700)
    for name, value in (('original.icns', original), ('candidate.icns', candidate),
                        ('native-parity.m', NATIVE_SOURCE.encode())):
        exclusive(run / name, value)
    exclusive(run / 'input-manifest.json', (json.dumps({
        'source_sha256': ORIGINAL_SHA256,
        'candidate_sha256': hashlib.sha256(candidate).hexdigest(),
        'fixture_source_sha256': hashlib.sha256(NATIVE_SOURCE.encode()).hexdigest(),
        'source_bytes': len(original), 'candidate_bytes': len(candidate),
        'status': 'prepared_not_yet_verified'}, sort_keys=True, indent=2) + '\n').encode())
    executable = run / 'native-parity'
    try:
        output = bounded_process(['/usr/bin/clang', '-fobjc-arc', '-fno-modules', '-Wall', '-Wextra', '-Werror',
                                  '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'ImageIO',
                                  '-framework', 'CoreGraphics', str(run / 'native-parity.m'), '-o', str(executable)],
                                 60, run, 'compile')
        require(not output, 'compile_unexpected_output')
        output = bounded_process([str(executable), str(run / 'original.icns'), str(run / 'candidate.icns')],
                                 30, run, 'parity')
        result = json.loads(output)
        require(isinstance(result, dict) and result.get('native_pixels_equal') is True and
                result.get('native_profiles_equal') is True and result.get('imageio_properties_equal') is True,
                'native_result_invalid')
        require(read_input(ORIGINAL) == original and
                read_input(run / 'original.icns') == original and read_input(run / 'candidate.icns') == candidate,
                'input_changed_after_native_read')
        result.update({'source_sha256': ORIGINAL_SHA256, 'candidate_sha256': hashlib.sha256(candidate).hexdigest(),
                       'fixture_source_sha256': hashlib.sha256(NATIVE_SOURCE.encode()).hexdigest(),
                       'source_bytes': len(original), 'candidate_bytes': len(candidate),
                       'inputs_unchanged': True, 'scope': 'data-only ImageIO and NSImage; no visual regeneration'})
        exclusive(run / 'result.json', (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
        print(json.dumps({'status': 'passed', 'evidence_directory': str(run), **result}, sort_keys=True))
        return 0
    except BaseException:
        exclusive(run / 'failure.json', b'{"status":"failed","reason":"native_parity_or_wrapper_refusal"}\n')
        print(json.dumps({'status': 'failed', 'evidence_directory': str(run)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
