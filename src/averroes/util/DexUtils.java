package averroes.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.raw.RawDexFile;

import com.google.common.base.MoreObjects;
import com.google.common.io.ByteStreams;

/**
 * 
 * @author Michael Appel 
 *	Provides dex related utils.
 */

public class DexUtils {
	
	/**
	 * dexlib2 does not provide means to return a raw dex file. This method serves
	 * as utility to return a object of type "RawDexFile" as defined in the dexlib2 library.
	 * @return
	 */
	public static RawDexFile getRawDex(File dexFile, String dexEntry, Opcodes opcodes) throws Exception {
        ZipFile zipFile = null;
        boolean isZipFile = false;
        try {
            zipFile = new ZipFile(dexFile);
            // if we get here, it's safe to assume we have a zip file
            isZipFile = true;

            String zipEntryName = MoreObjects.firstNonNull(dexEntry, "classes.dex");
            ZipEntry zipEntry = zipFile.getEntry(zipEntryName);
            if (zipEntry == null) {
                throw new FileNotFoundException("zip file" + dexFile.getName() + " does not contain a " + zipEntryName + " file");
            }
            long fileLength = zipEntry.getSize();
            if (fileLength < 40) {
                throw new Exception("The " + zipEntryName + " file in " + dexFile.getName() + " is too small to be a valid dex file");
            } else if (fileLength > Integer.MAX_VALUE) {
                throw new Exception("The " + zipEntryName + " file in " + dexFile.getName() + " is too large to read in");
            }
            byte[] dexBytes = new byte[(int)fileLength];
            ByteStreams.readFully(zipFile.getInputStream(zipEntry), dexBytes);
            return new RawDexFile(opcodes, dexBytes);
        } catch (IOException ex) {
            // don't continue on if we know it's a zip file
            if (isZipFile) {
                throw ex;
            }
        } finally {
            if (zipFile != null) {
                try {
                    zipFile.close();
                } catch (IOException ex) {
                    // just eat it
                }
            }
        }	
        return null;
	}

}
