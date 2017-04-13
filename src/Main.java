public class Main {

    private static CTR myCTR = new CTR();

    public static void main(String[] args) throws Exception {
        myCTR.doEncryption("input.txt","key.txt","output.txt");
        myCTR.doDecryption("output.txt","key.txt","input2.txt");
    }
}